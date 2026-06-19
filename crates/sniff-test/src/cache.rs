//! On-disk analysis cache schema.
//!
//! Cache files are keyed by compiled artifact identity, not only by crate name.
//! Cargo can compile multiple versions or feature combinations of the same crate
//! name in one build, and those artifacts must not share panic evidence.
//!
//! The schema intentionally stores structured findings and graph data. Terminal
//! concerns such as colors are applied later by the reporter.

use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const CACHE_FORMAT_VERSION: u32 = 1;
pub const CACHE_DIR_NAME: &str = "sniff-test-cache";
pub const CACHE_VERSION_DIR: &str = "v1";

/// Cached analysis for one exact rustc output artifact.
///
/// `functions` is keyed by fully qualified function path for direct lookup
/// once the consuming crate has resolved which artifact it called into.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CachedArtifactAnalysis {
    pub format_version: u32,
    pub tool_version: String,
    pub rustc_version: String,
    pub artifact: CachedArtifactInfo,
    pub dependencies: Vec<CachedDependencyRef>,
    pub functions: BTreeMap<String, CachedFunctionSummary>,
}

impl CachedArtifactAnalysis {
    #[must_use]
    pub fn new(
        tool_version: impl Into<String>,
        rustc_version: impl Into<String>,
        artifact: CachedArtifactInfo,
        dependencies: Vec<CachedDependencyRef>,
        functions: Vec<CachedFunctionSummary>,
    ) -> Self {
        let functions = functions
            .into_iter()
            .map(|function| (function.path.clone(), function))
            .collect();
        Self {
            format_version: CACHE_FORMAT_VERSION,
            tool_version: tool_version.into(),
            rustc_version: rustc_version.into(),
            artifact,
            dependencies,
            functions,
        }
    }
}

/// Identity and provenance for the compiled artifact represented by a cache file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CachedArtifactInfo {
    pub artifact_id: String,
    pub crate_name: String,
    pub crate_types: Vec<String>,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub manifest_path: Option<String>,
    pub target: Option<String>,
    pub metadata: Option<String>,
    pub extra_filename: Option<String>,
}

/// A dependency artifact observed while analyzing this artifact.
///
/// These references are mostly diagnostic and cache-hit metadata. Panic evidence
/// is looked up from the dependency artifact cache by `artifact_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CachedDependencyRef {
    pub extern_name: String,
    pub artifact_path: Option<String>,
    pub artifact_id: Option<String>,
    pub exact_cache_path: Option<String>,
}

/// Cached panic reachability facts for one analyzed report root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CachedFunctionSummary {
    pub path: String,
    pub is_generic: bool,
    pub has_panic_docs: bool,
    #[serde(default)]
    pub root_span: Option<CachedSourceSpan>,
    pub raw_panic_paths: usize,
    pub panic_obligations: usize,
    pub trusted_panic_obligations: usize,
    pub graph: Option<CachedReachabilityGraph>,
    pub findings: Vec<CachedFinding>,
}

impl CachedFunctionSummary {
    #[must_use]
    pub fn is_panic_reachable(&self) -> bool {
        self.has_panic_docs
            || self.raw_panic_paths > 0
            || self.panic_obligations > 0
            || self.trusted_panic_obligations > 0
    }
}

/// One concrete cached reason a function is panic-reachable or crosses a boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CachedFinding {
    pub kind: CachedFindingKind,
    pub span: String,
    #[serde(default)]
    pub source_span: Option<CachedSourceSpan>,
    #[serde(default)]
    pub diagnostic_spans: Vec<CachedDiagnosticSpan>,
    pub edge_index: Option<usize>,
    pub trace: Vec<usize>,
    pub reason: String,
    pub target: Option<CachedFindingTarget>,
}

/// Structured source range for later diagnostic rendering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CachedSourceSpan {
    pub file: String,
    pub line_start: usize,
    pub column_start: usize,
    pub line_end: usize,
    pub column_end: usize,
}

/// One labeled source range that can be rendered as a diagnostic span.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CachedDiagnosticSpan {
    pub span: CachedSourceSpan,
    pub is_primary: bool,
    pub label: Option<String>,
}

/// Semantic category for cached evidence.
///
/// The reporter maps these categories to labels, counts, and colors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CachedFindingKind {
    CompilerAssert,
    PanicInvocation,
    PanicObligation,
    TrustedPanicObligation,
    CrateBoundary,
}

/// Cached target of a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum CachedFindingTarget {
    Function {
        path: String,
        crate_name: String,
        is_local: bool,
    },
    Node {
        node_index: usize,
        label: String,
    },
}

/// Reachability graph captured in cache form.
///
/// The graph is per function summary for now. This duplicates some nodes across
/// roots, but keeps call trace rendering straightforward.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CachedReachabilityGraph {
    pub root: usize,
    pub nodes: Vec<CachedReachabilityNode>,
    pub edges: Vec<CachedReachabilityEdge>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CachedReachabilityNode {
    pub id: usize,
    pub depth: usize,
    pub kind: CachedReachabilityNodeKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum CachedReachabilityNodeKind {
    Instance {
        path: String,
        crate_name: String,
        is_local: bool,
    },
    CompilerAssert {
        message: String,
    },
    IndirectCall {
        callee_ty: String,
    },
    DynObjectCast {
        source_ty: String,
        target_ty: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CachedReachabilityEdge {
    pub source: usize,
    pub target: usize,
    pub kind: CachedReachabilityEdgeKind,
    pub span: String,
    #[serde(default)]
    pub source_span: Option<CachedSourceSpan>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CachedReachabilityEdgeKind {
    DirectCall,
    TailCall,
    FnPointerReify,
    ClosureFnPointerReify,
    ClosureDefinition,
    DynObjectCast,
    VTableEntry,
    ConstBody,
    Assert,
    IndirectCall,
}

#[derive(Debug)]
pub enum CacheError {
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
}

impl Display for CacheError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "failed to access {}: {source}", path.display())
            }
            Self::Json { path, source } => {
                write!(f, "failed to parse {}: {source}", path.display())
            }
            Self::Format { path, version } => write!(
                f,
                "unsupported cache format {version} in {}",
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
            Self::Format { .. } => None,
        }
    }
}

/// Writes an artifact analysis summary to the artifact cache and crate-name mirror.
///
/// # Errors
///
/// Returns an error when the cache directories cannot be created, the summary
/// cannot be serialized, or the cache file cannot be written.
pub fn write_artifact_analysis(
    cache_dir: &Path,
    analysis: &CachedArtifactAnalysis,
) -> Result<(), CacheError> {
    let artifact_path = artifact_cache_path(cache_dir, &analysis.artifact.artifact_id);
    let crate_path = crate_cache_path(
        cache_dir,
        &analysis.artifact.crate_name,
        &analysis.artifact.artifact_id,
    );
    let source = serde_json::to_string_pretty(analysis).map_err(|source| CacheError::Json {
        path: artifact_path.clone(),
        source,
    })?;

    write_atomic(&artifact_path, &source)?;
    write_atomic(&crate_path, &source)
}

/// Reads an artifact analysis summary from a cache file.
///
/// # Errors
///
/// Returns an error when the file cannot be read, the JSON cannot be parsed, or
/// the cache format version is unsupported.
pub fn read_artifact_analysis(path: &Path) -> Result<CachedArtifactAnalysis, CacheError> {
    let source = std::fs::read_to_string(path).map_err(|source| CacheError::Io {
        path: path.to_owned(),
        source,
    })?;
    let analysis = serde_json::from_str::<CachedArtifactAnalysis>(&source).map_err(|source| {
        CacheError::Json {
            path: path.to_owned(),
            source,
        }
    })?;
    if analysis.format_version == CACHE_FORMAT_VERSION {
        Ok(analysis)
    } else {
        Err(CacheError::Format {
            path: path.to_owned(),
            version: analysis.format_version,
        })
    }
}

#[must_use]
pub fn artifact_cache_path(cache_dir: &Path, artifact_id: &str) -> PathBuf {
    cache_dir
        .join("artifacts")
        .join(format!("{}.json", sanitize_path_component(artifact_id)))
}

#[must_use]
pub fn crate_cache_path(cache_dir: &Path, crate_name: &str, artifact_id: &str) -> PathBuf {
    cache_dir
        .join("crates")
        .join(sanitize_path_component(crate_name))
        .join(format!("{}.json", sanitize_path_component(artifact_id)))
}

#[must_use]
pub fn artifact_id(crate_name: &str, extra_filename: Option<&str>) -> String {
    format!("{}{}", crate_name, extra_filename.unwrap_or_default())
}

#[must_use]
pub fn artifact_id_from_extern_path(path: &Path) -> Option<String> {
    let stem = path.file_stem()?.to_str()?;
    Some(stem.strip_prefix("lib").unwrap_or(stem).to_owned())
}

#[must_use]
pub fn default_cache_dir(target_dir: impl AsRef<Path>) -> PathBuf {
    target_dir
        .as_ref()
        .join(CACHE_DIR_NAME)
        .join(CACHE_VERSION_DIR)
}

fn write_atomic(path: &Path, source: &str) -> Result<(), CacheError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| CacheError::Io {
            path: parent.to_owned(),
            source,
        })?;
    }

    let tmp_path = path.with_extension(format!("json.tmp.{}", std::process::id()));
    std::fs::write(&tmp_path, source).map_err(|source| CacheError::Io {
        path: tmp_path.clone(),
        source,
    })?;
    std::fs::rename(&tmp_path, path).map_err(|source| CacheError::Io {
        path: path.to_owned(),
        source,
    })
}

fn sanitize_path_component(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
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
    use super::{
        artifact_cache_path, artifact_id_from_extern_path, crate_cache_path, default_cache_dir,
    };

    #[test]
    fn dependency_artifact_ids_strip_lib_prefix_and_extension() {
        assert_eq!(
            artifact_id_from_extern_path(
                "/target/debug/deps/libsniff_test-29f0d61bb0b8d782.rmeta".as_ref()
            )
            .as_deref(),
            Some("sniff_test-29f0d61bb0b8d782")
        );
        assert_eq!(
            artifact_id_from_extern_path(
                "/target/debug/deps/libserde-a63a178ac1888490.rlib".as_ref()
            )
            .as_deref(),
            Some("serde-a63a178ac1888490")
        );
    }

    #[test]
    fn cache_paths_are_under_versioned_cache_root() {
        let root = default_cache_dir("/target/plugin-nightly");

        assert_eq!(
            artifact_cache_path(&root, "sniff_test-29f0")
                .display()
                .to_string(),
            "/target/plugin-nightly/sniff-test-cache/v1/artifacts/sniff_test-29f0.json"
        );
        assert_eq!(
            crate_cache_path(&root, "sniff-test", "sniff_test-29f0")
                .display()
                .to_string(),
            "/target/plugin-nightly/sniff-test-cache/v1/crates/sniff-test/sniff_test-29f0.json"
        );
    }
}
