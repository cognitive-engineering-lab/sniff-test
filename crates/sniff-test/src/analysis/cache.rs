//! Versioned on-disk envelope for policy-neutral artifact analysis IR.
//!
//! The cache contains extraction facts only. Lint levels, selected report
//! roots, interpreted findings, and rendered traces deliberately live outside
//! this schema so a workspace can reinterpret one dependency artifact under a
//! different policy without recompiling it.
//!
//! Format 16 persists the open typed fact database beside the remaining legacy
//! traversal IR. Both payloads describe the same exact rustc artifact
//! generation; neither may contain workspace/root evaluation state.

use std::fmt::{self, Display, Formatter};
use std::fs::File;
use std::io::{Read, Write as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::facts::encoded::ArtifactFactIr;
use super::facts::registry::SchemaRegistry;
use super::facts::view::ArtifactDbView;
use super::ir::{ArtifactAnalysisIr, FunctionBodyProvenanceIr};

pub(crate) const CACHE_FORMAT_VERSION: u32 = 16;
pub(crate) const CACHE_DIR_NAME: &str = "sniff-test-cache";
pub(crate) const CACHE_VERSION_DIR: &str = "v16";
/// Independent outer limit for one complete serialized cache envelope.
///
/// This limit protects allocation and parsing at the file boundary regardless
/// of the limits enforced by any IR stored inside the envelope. Readers and
/// writers enforce the same policy so every cache written here is readable.
pub(crate) const MAX_CACHE_FILE_BYTES: u64 = 512 * 1024 * 1024;

/// Cached policy-neutral analysis for one exact rustc output artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct ArtifactAnalysisCache {
    pub(crate) format_version: u32,
    pub(crate) tool_version: String,
    pub(crate) rustc_version: String,
    pub(crate) artifact: ArtifactInfo,
    pub(crate) dependencies: Vec<RustcArtifactId>,
    /// Remaining panic-call, safety, ambiguity, and completeness input.
    /// Compiler-assert authority does not read this legacy projection.
    pub(crate) legacy_ir: ArtifactAnalysisIr,
    /// Open, independently versioned compiler and human fact tables.
    pub(crate) facts: ArtifactFactIr,
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
        mut legacy_ir: ArtifactAnalysisIr,
        facts: ArtifactFactIr,
        schemas: &SchemaRegistry,
    ) -> Result<Self, CacheValidationError> {
        dependencies.sort_unstable();
        dependencies.dedup();
        legacy_ir.canonicalize();
        let analysis = Self {
            format_version: CACHE_FORMAT_VERSION,
            tool_version: tool_version.into(),
            rustc_version: rustc_version.into(),
            artifact,
            dependencies,
            legacy_ir,
            facts,
        };
        analysis.validate(schemas)?;
        Ok(analysis)
    }

    /// Writes this analysis to the path derived from its artifact identity.
    pub(crate) fn write(
        &self,
        cache_dir: &Path,
        schemas: &SchemaRegistry,
    ) -> Result<(), CacheError> {
        let path = artifact_cache_path(cache_dir, &self.artifact.id);
        self.validate(schemas)
            .map_err(|error| CacheError::invalid(&path, error))?;
        let source = serde_json::to_string_pretty(self).map_err(|source| CacheError::Json {
            path: path.clone(),
            source,
        })?;
        write_bounded_cache_source(&path, &source, MAX_CACHE_FILE_BYTES)
    }

    /// Reads and validates one v16 cache file against the active extraction
    /// environment.
    pub(crate) fn read(
        path: &Path,
        expected: &CacheExpectations<'_>,
        schemas: &SchemaRegistry,
    ) -> Result<Self, CacheError> {
        let source = read_bounded_cache_file(path, MAX_CACHE_FILE_BYTES)?;
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
            .validate(schemas)
            .map_err(|error| CacheError::invalid(path, error))?;
        Ok(analysis)
    }

    fn validate(&self, schemas: &SchemaRegistry) -> Result<(), CacheValidationError> {
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
        self.legacy_ir
            .validate()
            .map_err(|error| CacheValidationError::new(error.to_string()))?;
        for (index, body) in self.legacy_ir.functions.iter().enumerate() {
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
        ArtifactDbView::open(&self.facts, schemas)
            .map_err(|error| CacheValidationError::new(error.to_string()))?;
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
    TooLarge {
        path: PathBuf,
        max_bytes: u64,
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
            Self::TooLarge { path, max_bytes } => write!(
                formatter,
                "cache {} exceeds the maximum size of {max_bytes} bytes",
                path.display()
            ),
        }
    }
}

impl std::error::Error for CacheError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Json { source, .. } => Some(source),
            Self::Format { .. }
            | Self::Version { .. }
            | Self::Invalid { .. }
            | Self::TooLarge { .. } => None,
        }
    }
}

fn read_bounded_cache_file(path: &Path, max_bytes: u64) -> Result<String, CacheError> {
    let file = File::open(path).map_err(|source| CacheError::Io {
        path: path.to_owned(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| CacheError::Io {
        path: path.to_owned(),
        source,
    })?;
    if metadata.is_file() {
        ensure_cache_byte_limit(path, metadata.len(), max_bytes)?;
    }
    read_bounded_cache_source(file, path, max_bytes)
}

fn read_bounded_cache_source(
    reader: impl Read,
    path: &Path,
    max_bytes: u64,
) -> Result<String, CacheError> {
    let read_limit = max_bytes
        .checked_add(1)
        .expect("cache byte limit must leave room for an overflow sentinel");
    let mut bytes = Vec::new();
    reader
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|source| CacheError::Io {
            path: path.to_owned(),
            source,
        })?;
    let bytes_read = u64::try_from(bytes.len()).map_err(|_| CacheError::TooLarge {
        path: path.to_owned(),
        max_bytes,
    })?;
    ensure_cache_byte_limit(path, bytes_read, max_bytes)?;
    String::from_utf8(bytes).map_err(|source| CacheError::Io {
        path: path.to_owned(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, source),
    })
}

fn write_bounded_cache_source(path: &Path, source: &str, max_bytes: u64) -> Result<(), CacheError> {
    let source_bytes = u64::try_from(source.len()).map_err(|_| CacheError::TooLarge {
        path: path.to_owned(),
        max_bytes,
    })?;
    ensure_cache_byte_limit(path, source_bytes, max_bytes)?;
    write_atomic(path, source)
}

fn ensure_cache_byte_limit(
    path: &Path,
    actual_bytes: u64,
    max_bytes: u64,
) -> Result<(), CacheError> {
    if actual_bytes > max_bytes {
        Err(CacheError::TooLarge {
            path: path.to_owned(),
            max_bytes,
        })
    } else {
        Ok(())
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
    use std::io::Cursor;
    use std::path::Path;

    use serde::{Deserialize, Serialize};
    use serde_json::json;
    use tempfile::tempdir;

    use super::{
        ArtifactAnalysisCache, ArtifactInfo, CACHE_FORMAT_VERSION, CacheError, CacheExpectations,
        RustcArtifactId, artifact_cache_path, default_cache_dir, read_bounded_cache_file,
        read_bounded_cache_source, write_bounded_cache_source,
    };
    use crate::analysis::facts::encoded::{
        ArtifactFactIr, EncodedRow, EncodedTable, EntityRef, FACT_IR_FORMAT_VERSION, FactIndexRow,
        RelationIndexRow, RowRef, TableKind,
    };
    use crate::analysis::facts::registry::SchemaRegistry;
    use crate::analysis::facts::schema::{EntitySchema, PassId, RowSchema, SchemaId};
    use crate::analysis::facts::view::ArtifactDbView;
    use crate::analysis::ir::{
        ArtifactAnalysisIr, FunctionAttributesIr, FunctionBodyIr, FunctionBodyProvenanceIr,
        FunctionId,
    };
    use crate::namespace::{StableDefPathHash, StableInstanceHash};

    const LOCAL_STABLE_CRATE_ID: u64 = 1;

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case", deny_unknown_fields)]
    struct CacheEntity {
        name: String,
    }

    impl RowSchema for CacheEntity {
        const ID: &'static str = "sniff-test.cache-test.entity";
        const VERSION: u32 = 1;
    }

    impl EntitySchema for CacheEntity {
        type Key = String;

        fn key(&self) -> Self::Key {
            self.name.clone()
        }
    }

    fn schema(value: &str) -> SchemaId {
        SchemaId::new(value).expect("valid test schema ID")
    }

    fn schemas() -> SchemaRegistry {
        let mut schemas = SchemaRegistry::new();
        schemas.register_entity::<CacheEntity>().unwrap();
        schemas
    }

    fn facts() -> ArtifactFactIr {
        ArtifactFactIr {
            format_version: FACT_IR_FORMAT_VERSION,
            tables: vec![EncodedTable {
                schema: schema(CacheEntity::ID),
                version: CacheEntity::VERSION,
                kind: TableKind::Entity,
                rows: vec![EncodedRow {
                    stable_key: Some(json!("root")),
                    data: json!({ "name": "root" }),
                }],
            }],
            fact_index: Vec::new(),
            relation_index: Vec::new(),
        }
    }

    fn facts_with_unknown_table() -> ArtifactFactIr {
        let mut facts = facts();
        let unknown = schema("future.allocator.fact");
        facts.tables.push(EncodedTable {
            schema: unknown.clone(),
            version: 7,
            kind: TableKind::Fact,
            rows: vec![EncodedRow {
                stable_key: None,
                data: json!({ "allocator": "sample" }),
            }],
        });
        facts
            .tables
            .sort_by(|left, right| left.schema.cmp(&right.schema));
        facts.fact_index.push(FactIndexRow {
            fact: RowRef {
                schema: unknown,
                row: 0,
            },
            owner: None,
            anchor: None,
            provenance_root: None,
            requirements: Vec::new(),
            producer: PassId::new("future.allocator.collect").unwrap(),
        });
        facts
    }

    fn facts_with_dangling_relation() -> ArtifactFactIr {
        let node = schema("future.node");
        let edge = schema("future.edge");
        ArtifactFactIr {
            format_version: FACT_IR_FORMAT_VERSION,
            tables: vec![
                EncodedTable {
                    schema: edge.clone(),
                    version: 1,
                    kind: TableKind::Relation,
                    rows: vec![EncodedRow {
                        stable_key: None,
                        data: json!({}),
                    }],
                },
                EncodedTable {
                    schema: node.clone(),
                    version: 1,
                    kind: TableKind::Entity,
                    rows: vec![EncodedRow {
                        stable_key: Some(json!("only-node")),
                        data: json!({}),
                    }],
                },
            ],
            fact_index: Vec::new(),
            relation_index: vec![RelationIndexRow {
                relation: RowRef {
                    schema: edge,
                    row: 0,
                },
                from: EntityRef {
                    schema: node.clone(),
                    row: 0,
                },
                to: EntityRef {
                    schema: node,
                    row: 1,
                },
                source: None,
            }],
        }
    }

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

    fn analysis(schemas: &SchemaRegistry) -> ArtifactAnalysisCache {
        ArtifactAnalysisCache::new(
            "0.1.0",
            "rustc 1.90.0-nightly",
            artifact(),
            vec![rustc_id(2, "22222222222222222222222222222222")],
            ir(),
            facts(),
            schemas,
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
    fn bounded_cache_reader_accepts_the_exact_byte_limit() {
        let source =
            read_bounded_cache_source(Cursor::new(b"12345678"), Path::new("cache.json"), 8)
                .expect("input at the limit should be accepted");

        assert_eq!(source, "12345678");
    }

    #[test]
    fn bounded_cache_reader_rejects_input_over_the_byte_limit() {
        let error =
            read_bounded_cache_source(Cursor::new(b"123456789"), Path::new("cache.json"), 8)
                .expect_err("input beyond the limit should be rejected");

        assert!(matches!(error, CacheError::TooLarge { max_bytes: 8, .. }));
        assert_eq!(
            error.to_string(),
            "cache cache.json exceeds the maximum size of 8 bytes"
        );
    }

    #[test]
    fn bounded_cache_file_reader_rejects_input_over_the_byte_limit() {
        let directory = tempdir().expect("temporary cache root");
        let path = directory.path().join("cache.json");
        fs::write(&path, b"123456789").expect("write oversized input");

        let error = read_bounded_cache_file(&path, 8)
            .expect_err("a regular file beyond the limit should be rejected");

        assert!(matches!(error, CacheError::TooLarge { max_bytes: 8, .. }));
    }

    #[test]
    fn bounded_cache_writer_rejects_input_before_creating_the_file() {
        let directory = tempdir().expect("temporary cache root");
        let path = directory.path().join("cache.json");

        let error = write_bounded_cache_source(&path, "123456789", 8)
            .expect_err("output beyond the limit should be rejected");

        assert!(matches!(error, CacheError::TooLarge { max_bytes: 8, .. }));
        assert!(!path.exists());
    }

    #[test]
    fn v16_round_trip_preserves_legacy_and_typed_artifact_data() {
        let directory = tempdir().expect("temporary cache root");
        let schemas = schemas();
        let expected = analysis(&schemas);
        expected
            .write(directory.path(), &schemas)
            .expect("write cache");

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
                "facts",
                "format-version",
                "legacy-ir",
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

        let decoded =
            ArtifactAnalysisCache::read(&path, &expectations(), &schemas).expect("read cache");
        assert_eq!(decoded, expected);
        assert_eq!(decoded.legacy_ir, ir());
        assert_eq!(decoded.facts, facts());
        let facts = ArtifactDbView::open(&decoded.facts, &schemas).expect("typed cache view");
        assert_eq!(
            facts
                .table::<CacheEntity>()
                .unwrap()
                .iter()
                .collect::<Vec<_>>(),
            [&CacheEntity {
                name: String::from("root"),
            }]
        );
        assert_eq!(
            decoded.dependencies,
            [rustc_id(2, "22222222222222222222222222222222")]
        );
    }

    #[test]
    fn writing_same_rustc_artifact_identity_refreshes_cached_artifact_data() {
        let directory = tempdir().expect("temporary cache root");
        let schemas = schemas();
        let first = analysis(&schemas);
        let second = analysis(&schemas);

        first
            .write(directory.path(), &schemas)
            .expect("write first cache");
        second
            .write(directory.path(), &schemas)
            .expect("refresh first cache");

        let path = artifact_cache_path(directory.path(), &second.artifact.id);
        let decoded = ArtifactAnalysisCache::read(&path, &expectations(), &schemas)
            .expect("read refreshed cache");

        assert_eq!(decoded, second);
    }

    #[test]
    fn canonicalization_makes_dependency_order_irrelevant() {
        let schemas = schemas();
        let dependencies = vec![
            rustc_id(3, "33333333333333333333333333333333"),
            rustc_id(2, "22222222222222222222222222222222"),
        ];
        let forward = ArtifactAnalysisCache::new(
            "0.1.0",
            "rustc",
            artifact(),
            dependencies.clone(),
            ir(),
            facts(),
            &schemas,
        )
        .expect("valid analysis");
        let reverse = ArtifactAnalysisCache::new(
            "0.1.0",
            "rustc",
            artifact(),
            dependencies.into_iter().rev().collect(),
            ir(),
            facts(),
            &schemas,
        )
        .expect("valid analysis");

        assert_eq!(forward, reverse);
        assert_eq!(
            serde_json::to_vec_pretty(&forward).unwrap(),
            serde_json::to_vec_pretty(&reverse).unwrap()
        );
        assert_eq!(forward.dependencies[0].stable_crate_id, 2);
    }

    #[test]
    fn exact_duplicate_dependencies_are_deduplicated() {
        let schemas = schemas();
        let dependency = rustc_id(2, "22222222222222222222222222222222");
        let analysis = ArtifactAnalysisCache::new(
            "0.1.0",
            "rustc",
            artifact(),
            vec![dependency.clone(), dependency.clone()],
            ir(),
            facts(),
            &schemas,
        )
        .expect("duplicate graph edges are harmless");

        assert_eq!(analysis.dependencies, [dependency]);
    }

    #[test]
    fn new_rejects_invalid_cache_data() {
        let schemas = schemas();
        let mut invalid_artifact = artifact();
        invalid_artifact.id.svh = String::from("not-a-valid-svh");

        let error = ArtifactAnalysisCache::new(
            "0.1.0",
            "rustc",
            invalid_artifact,
            Vec::new(),
            ir(),
            facts(),
            &schemas,
        )
        .expect_err("malformed cache data must be rejected");

        assert!(error.to_string().contains("lowercase hexadecimal"));
    }

    #[test]
    fn accepts_exact_foreign_body_owned_as_a_consumer_instantiation() {
        let schemas = schemas();
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
            artifact(),
            Vec::new(),
            overlay_ir,
            facts(),
            &schemas,
        )
        .expect("the consumer artifact should own the exact foreign overlay");
    }

    #[test]
    fn unknown_fact_schemas_round_trip_as_opaque_tables() {
        let directory = tempdir().expect("temporary cache root");
        let schemas = schemas();
        let expected = ArtifactAnalysisCache::new(
            "0.1.0",
            "rustc 1.90.0-nightly",
            artifact(),
            Vec::new(),
            ir(),
            facts_with_unknown_table(),
            &schemas,
        )
        .expect("unknown tables remain valid");
        expected.write(directory.path(), &schemas).unwrap();

        let path = artifact_cache_path(directory.path(), &expected.artifact.id);
        let decoded = ArtifactAnalysisCache::read(&path, &expectations(), &schemas).unwrap();
        let view = ArtifactDbView::open(&decoded.facts, &schemas).unwrap();

        assert_eq!(
            view.opaque_tables()
                .map(|table| table.schema.as_str())
                .collect::<Vec<_>>(),
            ["future.allocator.fact"]
        );
        assert_eq!(decoded, expected);
    }

    #[test]
    fn known_schema_version_mismatches_are_rejected() {
        let schemas = schemas();
        let mut incompatible = facts();
        incompatible.tables[0].version += 1;

        let error = ArtifactAnalysisCache::new(
            "0.1.0",
            "rustc",
            artifact(),
            Vec::new(),
            ir(),
            incompatible,
            &schemas,
        )
        .expect_err("a known schema cannot be treated as opaque");

        assert!(error.to_string().contains(CacheEntity::ID));
        assert!(error.to_string().contains("incompatible"));
    }

    #[test]
    fn dangling_unknown_relation_endpoints_are_rejected() {
        let error = ArtifactAnalysisCache::new(
            "0.1.0",
            "rustc",
            artifact(),
            Vec::new(),
            ir(),
            facts_with_dangling_relation(),
            &SchemaRegistry::new(),
        )
        .expect_err("generic relation integrity applies to unknown schemas");

        assert!(error.to_string().contains("relation `to` endpoint"));
        assert!(error.to_string().contains("refers to missing row"));
    }

    #[test]
    fn read_reports_v15_as_incompatible_before_deserializing() {
        let directory = tempdir().expect("temporary cache root");
        let path = directory.path().join("legacy.json");
        fs::write(&path, r#"{"format-version":15,"ir":{}}"#).expect("write legacy header");

        let error = ArtifactAnalysisCache::read(&path, &expectations(), &schemas())
            .expect_err("v15 is deliberately incompatible");

        assert!(matches!(error, CacheError::Format { version: 15, .. }));
    }

    #[test]
    fn read_rejects_a_v16_envelope_without_the_fact_database() {
        let directory = tempdir().expect("temporary cache root");
        let path = directory.path().join("incomplete.json");
        let schemas = schemas();
        let mut document = serde_json::to_value(analysis(&schemas)).unwrap();
        document
            .as_object_mut()
            .expect("cache object")
            .remove("facts");
        fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();

        let error = ArtifactAnalysisCache::read(&path, &expectations(), &schemas)
            .expect_err("the v16 fact database is required");

        assert!(matches!(error, CacheError::Json { .. }));
        assert!(error.to_string().contains("missing field `facts`"));
    }

    #[test]
    fn read_rejects_a_v16_envelope_without_the_legacy_payload() {
        let directory = tempdir().expect("temporary cache root");
        let path = directory.path().join("incomplete.json");
        let schemas = schemas();
        let mut document = serde_json::to_value(analysis(&schemas)).unwrap();
        document
            .as_object_mut()
            .expect("cache object")
            .remove("legacy-ir");
        fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();

        let error = ArtifactAnalysisCache::read(&path, &expectations(), &schemas)
            .expect_err("the v16 legacy traversal payload is required");

        assert!(matches!(error, CacheError::Json { .. }));
        assert!(error.to_string().contains("missing field `legacy-ir`"));
    }

    #[test]
    fn read_rejects_the_v15_ir_field_inside_a_v16_envelope() {
        let directory = tempdir().expect("temporary cache root");
        let path = directory.path().join("aliased.json");
        let schemas = schemas();
        let mut document = serde_json::to_value(analysis(&schemas)).unwrap();
        let object = document.as_object_mut().expect("cache object");
        let legacy_ir = object.remove("legacy-ir").expect("legacy IR field");
        object.insert(String::from("ir"), legacy_ir);
        fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();

        let error = ArtifactAnalysisCache::read(&path, &expectations(), &schemas)
            .expect_err("the old payload field must not be accepted as an alias");

        assert!(matches!(error, CacheError::Json { .. }));
        assert!(error.to_string().contains("unknown field `ir`"));
    }

    #[test]
    fn cache_paths_use_the_v16_directory() {
        let root = default_cache_dir("/target/plugin-nightly");
        let identity = rustc_id(1, "0123456789abcdef0123456789abcdef");

        assert_eq!(
            root.to_string_lossy(),
            "/target/plugin-nightly/sniff-test-cache/v16"
        );
        assert_eq!(
            artifact_cache_path(&root, &identity).to_string_lossy(),
            "/target/plugin-nightly/sniff-test-cache/v16/artifacts/0000000000000001-0123456789abcdef0123456789abcdef.json"
        );
    }
}
