//! On-disk analysis cache schema.
//!
//! Cache files are keyed by compiled artifact identity, not only by crate name.
//! Cargo can compile multiple versions or feature combinations of the same crate
//! name in one build, and those artifacts must not share effect evidence.
//!
//! The schema intentionally stores structured findings and graph data. Terminal
//! concerns such as colors are applied later by the reporter.

use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const CACHE_FORMAT_VERSION: u32 = 10;
pub const CACHE_DIR_NAME: &str = "sniff-test-cache";
pub const CACHE_VERSION_DIR: &str = "v10";
pub const OUTCOME_FORMAT_VERSION: u32 = 2;

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

impl UnitOutcome {
    /// Writes this outcome under the cache directory.
    ///
    /// # Errors
    ///
    /// Returns an error when the outcome directory cannot be created or the
    /// file cannot be serialized or written.
    pub fn write(&self, cache_dir: &Path) -> Result<(), CacheError> {
        let path = outcome_cache_path(cache_dir, &self.artifact_id);
        let source = serde_json::to_string_pretty(self).map_err(|source| CacheError::Json {
            path: path.clone(),
            source,
        })?;
        write_atomic(&path, &source)
    }

    /// Reads an outcome for one artifact.
    ///
    /// # Errors
    ///
    /// Returns an error when the file is missing or unreadable, or was written
    /// by a different outcome format or sniff-test version.
    pub fn read(
        cache_dir: &Path,
        artifact_id: &str,
        expected_tool_version: &str,
    ) -> Result<Self, CacheError> {
        let path = outcome_cache_path(cache_dir, artifact_id);
        let source = std::fs::read_to_string(&path).map_err(|source| CacheError::Io {
            path: path.clone(),
            source,
        })?;
        let outcome = serde_json::from_str::<Self>(&source).map_err(|source| CacheError::Json {
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

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct CacheFormatHeader {
    format_version: u32,
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

    /// Writes this analysis to the artifact cache and crate-name mirror.
    ///
    /// # Errors
    ///
    /// Returns an error when the cache directories cannot be created, the
    /// analysis cannot be serialized, or a cache file cannot be written.
    pub fn write(&self, cache_dir: &Path) -> Result<(), CacheError> {
        let artifact_path = artifact_cache_path(cache_dir, &self.artifact.artifact_id);
        let crate_path = crate_cache_path(
            cache_dir,
            &self.artifact.crate_name,
            &self.artifact.artifact_id,
        );
        let source = serde_json::to_string_pretty(self).map_err(|source| CacheError::Json {
            path: artifact_path.clone(),
            source,
        })?;

        write_atomic(&artifact_path, &source)?;
        write_atomic(&crate_path, &source)
    }

    /// Reads an analysis from a cache file.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read, the JSON cannot be
    /// parsed, the cache format version is unsupported, or the file was
    /// written by a different sniff-test or rustc version than `expected`.
    pub fn read(path: &Path, expected: &CacheExpectations<'_>) -> Result<Self, CacheError> {
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
}

/// Identity and provenance for the compiled artifact represented by a cache file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CachedArtifactInfo {
    pub artifact_id: String,
    pub crate_name: String,
}

/// A dependency artifact observed while analyzing this artifact.
///
/// These references are mostly diagnostic and cache-hit metadata. Effect evidence
/// is looked up from the dependency artifact cache by `artifact_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CachedDependencyRef {
    pub extern_name: String,
    pub artifact_id: String,
}

/// Cached effect facts for one analyzed report root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CachedFunctionSummary {
    /// Session-independent identity (see `namespace::stable_def_path_hash`).
    pub def_path_hash: String,
    /// Display form as rendered by the defining crate's session.
    pub path: String,
    pub is_generic: bool,
    pub root_span: Option<CachedSourceSpan>,
    pub panic: CachedEffectSummary,
    pub safety: CachedEffectSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CachedEffectSummary {
    /// False when a reachability query halted at the node limit; the findings
    /// then under-approximate and consumers must not treat this summary as
    /// exhaustive.
    pub analysis_complete: bool,
    pub has_contract: bool,
    pub graph: CachedReachabilityGraph,
    pub findings: Vec<CachedFinding>,
}

impl CachedEffectSummary {
    #[must_use]
    pub fn trace(&self, finding: &CachedFinding) -> Vec<CachedTraceStep> {
        let mut trace = finding
            .trace
            .iter()
            .filter_map(|edge_id| {
                let edge = self.graph.edges.iter().find(|edge| edge.id == *edge_id)?;
                let source = self
                    .graph
                    .nodes
                    .iter()
                    .find(|node| node.id == edge.source)?;
                let target = self
                    .graph
                    .nodes
                    .iter()
                    .find(|node| node.id == edge.target)?;
                Some(CachedTraceStep {
                    span: edge.span.clone(),
                    source: source.kind.clone(),
                    kind: edge.kind,
                    target: target.kind.clone(),
                })
            })
            .collect::<Vec<_>>();
        trace.extend(finding.dependency_trace.iter().cloned());
        trace
    }

    #[must_use]
    pub fn is_reachable(&self) -> bool {
        self.has_contract
            || self
                .findings
                .iter()
                .any(|finding| finding.kind.is_effect_evidence())
    }
}

/// One concrete cached effect site, obligation, or analysis boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CachedFinding {
    pub kind: CachedFindingKind,
    pub span: String,
    pub source_span: Option<CachedSourceSpan>,
    pub diagnostic_spans: Vec<CachedDiagnosticSpan>,
    /// Arena edge id of the triggering edge; resolves against
    /// [`CachedReachabilityEdge::id`] in this summary's `graph`.
    pub edge_index: Option<usize>,
    /// Arena edge ids from the root to the finding, same id space as
    /// `edge_index`.
    pub trace: Vec<usize>,
    /// Trace steps inherited from nested dependency caches. These cannot refer
    /// to this summary's graph id space, so rebasing flattens them structurally.
    pub dependency_trace: Vec<CachedTraceStep>,
    pub reason: String,
    pub missing_requirements: Vec<CachedRequirement>,
    pub target: Option<CachedFindingTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CachedTraceStep {
    pub span: String,
    pub source: CachedReachabilityNodeKind,
    pub kind: CachedReachabilityEdgeKind,
    pub target: CachedReachabilityNodeKind,
}

pub type CachedRequirement = crate::contracts::ContractRequirement;

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
    UnsafeCallMissingJustification,
    UnsafeCallMissingRequirements,
    UnsafeOpMissingJustification,
    SafetyObligationMissingJustification,
    SafetyObligationMissingRequirements,
}

impl CachedFindingKind {
    fn is_effect_evidence(self) -> bool {
        self != Self::CrateBoundary
    }

    pub(crate) fn is_panic(self) -> bool {
        matches!(
            self,
            Self::CompilerAssert
                | Self::PanicInvocation
                | Self::PanicObligation
                | Self::TrustedPanicObligation
                | Self::IndirectCallBoundary
        )
    }

    pub(crate) fn is_safety(self) -> bool {
        matches!(
            self,
            Self::UnsafeCallMissingJustification
                | Self::UnsafeCallMissingRequirements
                | Self::UnsafeOpMissingJustification
                | Self::SafetyObligationMissingJustification
                | Self::SafetyObligationMissingRequirements
        )
    }

    pub(crate) fn is_raw_effect(self) -> bool {
        matches!(
            self,
            Self::CompilerAssert
                | Self::PanicInvocation
                | Self::IndirectCallBoundary
                | Self::UnsafeCallMissingJustification
                | Self::UnsafeCallMissingRequirements
                | Self::UnsafeOpMissingJustification
                | Self::SafetyObligationMissingJustification
                | Self::SafetyObligationMissingRequirements
        )
    }
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
    MacroExpansion {
        path: String,
        crate_name: String,
        is_local: bool,
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
    /// Arena edge id, the id space [`CachedFinding::edge_index`] and
    /// [`CachedFinding::trace`] refer to. Edges are serialized as the
    /// snapshot's subsequence of the arena, so positions do not equal ids.
    pub id: usize,
    pub source: usize,
    pub target: usize,
    pub kind: CachedReachabilityEdgeKind,
    pub span: String,
    pub source_span: Option<CachedSourceSpan>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CachedReachabilityEdgeKind {
    DirectCall,
    TailCall,
    FnPointerReify,
    ClosureFnPointerReify,
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
        CacheError, CacheExpectations, CachedArtifactAnalysis, CachedArtifactInfo,
        CachedEffectSummary, CachedFinding, CachedFindingKind, CachedFunctionSummary,
        artifact_cache_path, artifact_id_from_extern_path, crate_cache_path, default_cache_dir,
        write_atomic,
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
            "/target/plugin-nightly/sniff-test-cache/v10/artifacts/sniff_test-29f0.json"
        );
        assert_eq!(
            crate_cache_path(&root, "sniff-test", "sniff_test-29f0")
                .display()
                .to_string(),
            "/target/plugin-nightly/sniff-test-cache/v10/crates/sniff-test/sniff_test-29f0.json"
        );
    }

    #[test]
    fn crate_boundaries_are_not_effect_evidence() {
        assert!(!effect_summary([CachedFindingKind::CrateBoundary]).is_reachable());
    }

    #[test]
    fn effect_findings_are_reachable() {
        assert!(effect_summary([CachedFindingKind::CompilerAssert]).is_reachable());
    }

    #[test]
    fn function_cache_uses_named_effect_summaries() {
        let function = CachedFunctionSummary {
            def_path_hash: String::from("hash"),
            path: String::from("demo::root"),
            is_generic: false,
            root_span: None,
            panic: effect_summary([]),
            safety: effect_summary([]),
        };

        let value = serde_json::to_value(function).expect("serialize function cache");
        assert!(value.get("panic").is_some());
        assert!(value.get("safety").is_some());
        assert!(value.get("effects").is_none());
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
        assert_eq!(
            CachedArtifactAnalysis::read(&path, &current).expect("read"),
            good
        );

        write(&analysis("0.0.9", "rustc 1.97.0-nightly"));
        assert!(matches!(
            CachedArtifactAnalysis::read(&path, &current),
            Err(CacheError::Version {
                field: "sniff-test",
                ..
            })
        ));

        write(&analysis("0.1.0", "rustc 1.96.0-nightly"));
        assert!(matches!(
            CachedArtifactAnalysis::read(&path, &current),
            Err(CacheError::Version { field: "rustc", .. })
        ));

        let mut unsupported_format = analysis("0.1.0", "rustc 1.97.0-nightly");
        unsupported_format.format_version = 3;
        write(&unsupported_format);
        assert!(matches!(
            CachedArtifactAnalysis::read(&path, &current),
            Err(CacheError::Format { version: 3, .. })
        ));

        write_atomic(&path, r#"{"format-version":9}"#).expect("write legacy header");
        assert!(matches!(
            CachedArtifactAnalysis::read(&path, &current),
            Err(CacheError::Format { version: 9, .. })
        ));
    }

    fn analysis(tool_version: &str, rustc_version: &str) -> CachedArtifactAnalysis {
        CachedArtifactAnalysis::new(
            tool_version,
            rustc_version,
            CachedArtifactInfo {
                artifact_id: String::from("dep-1234"),
                crate_name: String::from("dep"),
            },
            Vec::new(),
            Vec::new(),
        )
    }

    fn effect_summary(kinds: impl IntoIterator<Item = CachedFindingKind>) -> CachedEffectSummary {
        CachedEffectSummary {
            analysis_complete: true,
            has_contract: false,
            graph: super::CachedReachabilityGraph {
                root: 0,
                nodes: Vec::new(),
                edges: Vec::new(),
            },
            findings: kinds
                .into_iter()
                .map(|kind| CachedFinding {
                    kind,
                    span: String::new(),
                    source_span: None,
                    diagnostic_spans: Vec::new(),
                    edge_index: None,
                    trace: Vec::new(),
                    dependency_trace: Vec::new(),
                    reason: String::new(),
                    missing_requirements: Vec::new(),
                    target: None,
                })
                .collect(),
        }
    }
}
