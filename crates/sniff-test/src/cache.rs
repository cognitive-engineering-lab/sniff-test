//! On-disk analysis cache schema.
//!
//! Cache files are keyed by compiled artifact identity, not only by crate name.
//! Cargo can compile multiple versions or feature combinations of the same crate
//! name in one build, and those artifacts must not share panic evidence.
//!
//! The schema intentionally stores structured findings and only the trace data
//! they reference. Terminal concerns such as colors are applied later by the
//! reporter.

use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const CACHE_FORMAT_VERSION: u32 = 4;
pub const CACHE_DIR_NAME: &str = "sniff-test-cache";
pub const CACHE_VERSION_DIR: &str = "v4";
pub const OUTCOME_FORMAT_VERSION: u32 = 1;

/// Per-unit verdict persisted with artifact lifetime.
///
/// Cargo never re-invokes the `RUSTC_WRAPPER` driver for fresh units, so
/// run-scoped state cannot see their findings. An outcome stays valid exactly
/// as long as cargo considers its unit fresh: config, tool, argument, and
/// rustc changes all force rebuilds through the injected fingerprint inputs,
/// and rebuilds rewrite it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct UnitOutcome {
    pub format_version: u32,
    pub tool_version: String,
    pub artifact_id: String,
    pub has_denied_findings: bool,
    /// The exact report line emitted for this unit; the frontend re-prints it
    /// for fresh units whose driver never ran, since cargo replays only
    /// cached stderr, not stdout.
    pub report_json: Option<String>,
}

/// Writes a unit outcome under the cache directory.
///
/// # Errors
///
/// Returns an error when the outcome directory cannot be created or the file
/// cannot be serialized or written.
pub fn write_unit_outcome(cache_dir: &Path, outcome: &UnitOutcome) -> Result<(), CacheError> {
    let path = outcome_cache_path(cache_dir, &outcome.artifact_id);
    let source = serde_json::to_string_pretty(outcome).map_err(|source| CacheError::Json {
        path: path.clone(),
        source,
    })?;
    write_atomic(&path, &source)
}

/// Reads a unit outcome for one artifact.
///
/// # Errors
///
/// Returns an error when the file is missing or unreadable, or was written by
/// a different outcome format or sniff-test version.
pub fn read_unit_outcome(
    cache_dir: &Path,
    artifact_id: &str,
    expected_tool_version: &str,
) -> Result<UnitOutcome, CacheError> {
    let path = outcome_cache_path(cache_dir, artifact_id);
    let source = std::fs::read_to_string(&path).map_err(|source| CacheError::Io {
        path: path.clone(),
        source,
    })?;
    let outcome =
        serde_json::from_str::<UnitOutcome>(&source).map_err(|source| CacheError::Json {
            path: path.clone(),
            source,
        })?;
    if outcome.format_version != OUTCOME_FORMAT_VERSION {
        return Err(CacheError::Format {
            path,
            version: outcome.format_version,
        });
    }
    if outcome.tool_version != expected_tool_version {
        return Err(CacheError::Version {
            path,
            field: "sniff-test",
            found: outcome.tool_version,
            expected: expected_tool_version.to_owned(),
        });
    }
    Ok(outcome)
}

fn outcome_cache_path(cache_dir: &Path, artifact_id: &str) -> PathBuf {
    cache_dir
        .join("outcomes")
        .join(format!("{}.json", sanitize_path_component(artifact_id)))
}

/// Cached analysis for one exact rustc output artifact.
///
/// `functions` is keyed by [`CachedFunctionSummary::def_path_hash`] for direct
/// lookup once the consuming crate has resolved which artifact it called into.
/// Pretty-printed paths are not identity: they render differently in the
/// defining crate's session and a consumer's session.
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
            .map(|function| (function.def_path_hash.clone(), function))
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
    /// Session-independent identity (see `namespace::stable_def_path_hash`).
    pub def_path_hash: String,
    /// Display form as rendered by the defining crate's session.
    pub path: String,
    pub is_generic: bool,
    /// False when a reachability query halted at the node limit; the counts
    /// below then under-approximate and consumers must not treat this summary
    /// as exhaustive.
    #[serde(default = "default_analysis_complete")]
    pub analysis_complete: bool,
    pub has_panic_docs: bool,
    #[serde(default)]
    pub root_span: Option<CachedSourceSpan>,
    pub raw_panic_paths: usize,
    pub panic_obligations: usize,
    pub trusted_panic_obligations: usize,
    pub trace_arena: CachedTraceArena,
    pub findings: Vec<CachedFinding>,
}

fn default_analysis_complete() -> bool {
    true
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
    /// Ordered frame indices from the root to the finding. Each index resolves
    /// against this summary's [`CachedTraceArena::frames`].
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
    IndirectCallBoundary,
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
        label: String,
    },
}

/// The trace nodes and frames referenced by one function summary's findings.
///
/// Indices are local to the summary. Unreferenced reachability data is omitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CachedTraceArena {
    pub nodes: Vec<CachedTraceNode>,
    pub frames: Vec<CachedTraceFrame>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum CachedTraceNode {
    Function {
        path: String,
    },
    CompilerAssert {
        message: String,
    },
    Macro {
        path: String,
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
pub struct CachedTraceFrame {
    pub from: usize,
    pub to: usize,
    pub kind: CachedTraceFrameKind,
    pub span: String,
    #[serde(default)]
    pub source_span: Option<CachedSourceSpan>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CachedTraceFrameKind {
    DirectCall,
    TailCall,
    FnPointerReify,
    ClosureFnPointerReify,
    ClosureDefinition,
    FnPointerCallTarget,
    DynObjectCast,
    VTableEntry,
    DynDispatchVTableEntry,
    MacroExpansion,
    ConstBody,
    Assert,
    IndirectCall,
}

/// Session identity a cache file must match to be consumed as current
/// evidence.
///
/// Artifact ids alone cannot guarantee this: cargo hashes only the release
/// channel into `extra-filename`, so ids collide across nightlies, and they
/// never encode the sniff-test version at all. That is harmless under the
/// default cache dir (already rustc-scoped) but not with `--cache-dir`.
#[derive(Debug, Clone, Copy)]
pub struct CacheExpectations<'a> {
    pub tool_version: &'a str,
    pub rustc_version: &'a str,
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
    Version {
        path: PathBuf,
        field: &'static str,
        found: String,
        expected: String,
    },
}

impl CacheError {
    /// True for the routine miss of a dependency that simply has no cache
    /// file, such as sysroot crates.
    #[must_use]
    pub fn is_missing_file(&self) -> bool {
        matches!(
            self,
            Self::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound
        )
    }
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
            Self::Version {
                path,
                field,
                found,
                expected,
            } => write!(
                f,
                "stale cache {}: written by {field} {found}, current is {expected}",
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
            Self::Format { .. } | Self::Version { .. } => None,
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
/// Returns an error when the file cannot be read, the JSON cannot be parsed,
/// the cache format version is unsupported, or the file was written by a
/// different sniff-test or rustc version than `expected`.
pub fn read_artifact_analysis(
    path: &Path,
    expected: &CacheExpectations<'_>,
) -> Result<CachedArtifactAnalysis, CacheError> {
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
    if analysis.format_version != CACHE_FORMAT_VERSION {
        return Err(CacheError::Format {
            path: path.to_owned(),
            version: analysis.format_version,
        });
    }
    for (field, found, expected) in [
        ("sniff-test", &analysis.tool_version, expected.tool_version),
        ("rustc", &analysis.rustc_version, expected.rustc_version),
    ] {
        if found != expected {
            return Err(CacheError::Version {
                path: path.to_owned(),
                field,
                found: found.clone(),
                expected: expected.to_owned(),
            });
        }
    }
    Ok(analysis)
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
        CacheError, CacheExpectations, CachedArtifactAnalysis, CachedArtifactInfo, CachedFinding,
        CachedFindingKind, CachedFunctionSummary, CachedTraceArena, CachedTraceFrame,
        CachedTraceFrameKind, CachedTraceNode, artifact_cache_path, artifact_id_from_extern_path,
        crate_cache_path, default_cache_dir, read_artifact_analysis, write_atomic,
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
            "/target/plugin-nightly/sniff-test-cache/v4/artifacts/sniff_test-29f0.json"
        );
        assert_eq!(
            crate_cache_path(&root, "sniff-test", "sniff_test-29f0")
                .display()
                .to_string(),
            "/target/plugin-nightly/sniff-test-cache/v4/crates/sniff-test/sniff_test-29f0.json"
        );
    }

    #[test]
    fn cache_reads_reject_other_tool_rustc_and_format_versions() {
        let current = CacheExpectations {
            tool_version: "0.1.0",
            rustc_version: "rustc 1.97.0-nightly",
        };
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("artifact.json");
        let write = |analysis: &CachedArtifactAnalysis| {
            write_atomic(&path, &serde_json::to_string(analysis).expect("serialize"))
                .expect("write cache file");
        };

        let good = analysis("0.1.0", "rustc 1.97.0-nightly");
        write(&good);
        assert_eq!(read_artifact_analysis(&path, &current).expect("read"), good);

        write(&analysis("0.0.9", "rustc 1.97.0-nightly"));
        assert!(matches!(
            read_artifact_analysis(&path, &current),
            Err(CacheError::Version {
                field: "sniff-test",
                ..
            })
        ));

        write(&analysis("0.1.0", "rustc 1.96.0-nightly"));
        assert!(matches!(
            read_artifact_analysis(&path, &current),
            Err(CacheError::Version { field: "rustc", .. })
        ));

        let mut old_format = analysis("0.1.0", "rustc 1.97.0-nightly");
        old_format.format_version = 3;
        write(&old_format);
        assert!(matches!(
            read_artifact_analysis(&path, &current),
            Err(CacheError::Format { version: 3, .. })
        ));
    }

    #[test]
    fn function_summaries_store_compact_trace_arenas_instead_of_graphs() {
        let summary = CachedFunctionSummary {
            def_path_hash: String::from("00000000000000010000000000000002"),
            path: String::from("dep::run"),
            is_generic: false,
            analysis_complete: true,
            has_panic_docs: false,
            root_span: None,
            raw_panic_paths: 1,
            panic_obligations: 0,
            trusted_panic_obligations: 0,
            trace_arena: CachedTraceArena {
                nodes: vec![
                    CachedTraceNode::Function {
                        path: String::from("dep::run"),
                    },
                    CachedTraceNode::Function {
                        path: String::from("core::panicking::panic"),
                    },
                ],
                frames: vec![CachedTraceFrame {
                    from: 0,
                    to: 1,
                    kind: CachedTraceFrameKind::DirectCall,
                    span: String::from("src/lib.rs:2:5"),
                    source_span: None,
                }],
            },
            findings: vec![CachedFinding {
                kind: CachedFindingKind::PanicInvocation,
                span: String::from("src/lib.rs:2:5"),
                source_span: None,
                diagnostic_spans: Vec::new(),
                trace: vec![0],
                reason: String::from("panic invocation"),
                target: None,
            }],
        };

        let json = serde_json::to_value(summary).expect("serialize function summary");
        let object = json.as_object().expect("function summary object");
        assert!(object.contains_key("trace-arena"));
        assert!(!object.contains_key("graph"));
        let arena = object["trace-arena"]
            .as_object()
            .expect("trace arena object");
        assert_eq!(arena["nodes"].as_array().expect("trace nodes").len(), 2);
        assert_eq!(arena["frames"][0]["from"], 0);
        assert_eq!(arena["frames"][0]["to"], 1);
        assert_eq!(arena["frames"][0]["kind"], "direct-call");
        let finding = object["findings"][0].as_object().expect("finding object");
        assert!(!finding.contains_key("edge-index"));
        assert_eq!(finding["trace"], serde_json::json!([0]));
    }

    fn analysis(tool_version: &str, rustc_version: &str) -> CachedArtifactAnalysis {
        CachedArtifactAnalysis::new(
            tool_version,
            rustc_version,
            CachedArtifactInfo {
                artifact_id: String::from("dep-1234"),
                crate_name: String::from("dep"),
                crate_types: Vec::new(),
                package_name: None,
                package_version: None,
                manifest_path: None,
                target: None,
                metadata: None,
                extra_filename: None,
            },
            Vec::new(),
            Vec::new(),
        )
    }
}
