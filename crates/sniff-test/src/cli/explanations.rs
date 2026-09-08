//! Stable diagnostic-group handles and the current explanation report.
//!
//! A handle deliberately identifies a small semantic group rather than one
//! invocation. The report is replaced after each Cargo invocation; no history
//! or source-freshness database is maintained here.

use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

const EXPLANATION_FORMAT_VERSION: u32 = 2;
const EXPLANATION_FILE: &str = "explain.json";
const DIAGNOSTIC_GROUP_HANDLE_LEN: usize = 4;
const CROCKFORD_BASE32: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// Stable dimensions shared by diagnostics that should be explained together.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct DiagnosticGroupKey {
    lint: String,
    function: String,
    subtype: String,
}

impl DiagnosticGroupKey {
    #[must_use]
    pub(crate) fn new(
        lint: impl Into<String>,
        function: impl Into<String>,
        subtype: impl Into<String>,
    ) -> Self {
        Self {
            lint: lint.into(),
            function: function.into(),
            subtype: subtype.into(),
        }
    }

    #[must_use]
    pub(crate) fn handle(&self) -> DiagnosticGroupHandle {
        let mut hash = 0xcbf2_9ce4_8422_2325;
        hash_bytes(&mut hash, b"sniff-test.diagnostic-group-key\0\x01");
        hash_field(&mut hash, b'l', self.lint.as_bytes());
        hash_field(&mut hash, b'f', self.function.as_bytes());
        hash_field(&mut hash, b's', self.subtype.as_bytes());
        DiagnosticGroupHandle::from_hash(hash)
    }

    #[must_use]
    pub(crate) fn function(&self) -> &str {
        &self.function
    }

    #[must_use]
    pub(crate) fn subtype(&self) -> &str {
        &self.subtype
    }

    fn validate(&self) -> Result<(), String> {
        if self.lint.is_empty() {
            return Err(String::from("diagnostic group has no lint code"));
        }
        if self.function.is_empty() {
            return Err(String::from("diagnostic group has no function scope"));
        }
        Ok(())
    }
}

fn hash_field(hash: &mut u64, tag: u8, value: &[u8]) {
    hash_bytes(hash, &[tag]);
    hash_bytes(hash, &(value.len() as u64).to_be_bytes());
    hash_bytes(hash, value);
}

fn hash_bytes(hash: &mut u64, value: &[u8]) {
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    for byte in value {
        *hash = (*hash ^ u64::from(*byte)).wrapping_mul(FNV_PRIME);
    }
}

/// Four-character selector for a semantic group in the current report.
///
/// Handles are intentionally non-unique. All matching groups are retained.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct DiagnosticGroupHandle(String);

impl DiagnosticGroupHandle {
    fn from_hash(hash: u64) -> Self {
        let mut handle = String::with_capacity(DIAGNOSTIC_GROUP_HANDLE_LEN);
        for index in 0..DIAGNOSTIC_GROUP_HANDLE_LEN {
            let shift = 64 - (index + 1) * 5;
            let digit = ((hash >> shift) & 0x1f) as usize;
            handle.push(char::from(CROCKFORD_BASE32[digit]));
        }
        Self(handle)
    }

    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for DiagnosticGroupHandle {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParseDiagnosticGroupHandleError;

impl Display for ParseDiagnosticGroupHandleError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("expected a four-character diagnostic group handle")
    }
}

impl std::error::Error for ParseDiagnosticGroupHandleError {}

impl FromStr for DiagnosticGroupHandle {
    type Err = ParseDiagnosticGroupHandleError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let normalized = value.to_ascii_lowercase();
        if normalized.len() != DIAGNOSTIC_GROUP_HANDLE_LEN
            || !normalized
                .bytes()
                .all(|byte| CROCKFORD_BASE32.contains(&byte))
        {
            return Err(ParseDiagnosticGroupHandleError);
        }
        Ok(Self(normalized))
    }
}

/// One complete diagnostic omitted from compact output.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct StoredDiagnostic {
    group: DiagnosticGroupKey,
    summary: String,
    /// Complete native rustc diagnostic, including its ANSI styles and heading.
    explanation: String,
}

impl StoredDiagnostic {
    #[must_use]
    pub(crate) fn new(
        group: DiagnosticGroupKey,
        summary: impl Into<String>,
        explanation: impl Into<String>,
    ) -> Self {
        Self {
            group,
            summary: summary.into(),
            explanation: explanation.into(),
        }
    }

    #[must_use]
    pub(crate) fn explanation(&self) -> &str {
        &self.explanation
    }

    fn validate(&self) -> Result<(), String> {
        self.group.validate()?;
        if self.summary.is_empty() {
            return Err(String::from("stored diagnostic has no summary"));
        }
        Ok(())
    }
}

/// Diagnostics emitted by one rustc process during the current Cargo invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct ArtifactExplanation {
    diagnostics: Vec<StoredDiagnostic>,
}

impl ArtifactExplanation {
    pub(crate) fn new(diagnostics: Vec<StoredDiagnostic>) -> Result<Self, ExplanationStoreError> {
        let artifact = Self { diagnostics };
        artifact
            .validate()
            .map_err(ExplanationStoreError::Invalid)?;
        Ok(artifact)
    }

    fn validate(&self) -> Result<(), String> {
        for diagnostic in &self.diagnostics {
            diagnostic.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct ExplanationReport {
    format_version: u32,
    diagnostics: Vec<StoredDiagnostic>,
}

impl ExplanationReport {
    fn new(mut diagnostics: Vec<StoredDiagnostic>) -> Result<Self, ExplanationStoreError> {
        diagnostics.sort_unstable();
        diagnostics.dedup();
        let report = Self {
            format_version: EXPLANATION_FORMAT_VERSION,
            diagnostics,
        };
        report.validate().map_err(ExplanationStoreError::Invalid)?;
        Ok(report)
    }

    fn validate(&self) -> Result<(), String> {
        if self.format_version != EXPLANATION_FORMAT_VERSION {
            return Err(format!(
                "unsupported explanation format {}; expected {}; rerun cargo sniff-test to refresh it",
                self.format_version, EXPLANATION_FORMAT_VERSION
            ));
        }
        for diagnostic in &self.diagnostics {
            diagnostic.validate()?;
        }
        Ok(())
    }
}

/// All diagnostics belonging to one semantic group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExplanationGroup {
    key: DiagnosticGroupKey,
    diagnostics: Vec<StoredDiagnostic>,
}

impl ExplanationGroup {
    #[must_use]
    pub(crate) const fn key(&self) -> &DiagnosticGroupKey {
        &self.key
    }

    #[must_use]
    pub(crate) fn diagnostics(&self) -> &[StoredDiagnostic] {
        &self.diagnostics
    }
}

/// Single-report explanation store rooted under a sniff-test cache directory.
#[derive(Debug, Clone)]
pub(crate) struct ExplanationStore {
    cache_dir: PathBuf,
}

impl ExplanationStore {
    #[must_use]
    pub(crate) fn new(cache_dir: impl Into<PathBuf>) -> Self {
        Self {
            cache_dir: cache_dir.into(),
        }
    }

    /// Writes one rustc sidecar before its compact diagnostics are emitted.
    pub(crate) fn write_sidecar(
        staging_dir: &Path,
        artifact: &ArtifactExplanation,
    ) -> Result<(), ExplanationStoreError> {
        artifact
            .validate()
            .map_err(ExplanationStoreError::Invalid)?;
        write_sidecar_json(staging_dir, artifact)
    }

    /// Replaces the sole explanation report with all completed rustc sidecars.
    pub(crate) fn publish(&self, staging_dir: &Path) -> Result<(), ExplanationStoreError> {
        let mut diagnostics = Vec::new();
        let entries = fs::read_dir(staging_dir).map_err(|source| ExplanationStoreError::Io {
            path: staging_dir.to_owned(),
            source,
        })?;
        for entry in entries {
            let path = entry
                .map_err(|source| ExplanationStoreError::Io {
                    path: staging_dir.to_owned(),
                    source,
                })?
                .path();
            if path.extension().is_none_or(|extension| extension != "json") {
                continue;
            }
            let artifact: ArtifactExplanation = read_json(&path)?;
            artifact
                .validate()
                .map_err(|reason| ExplanationStoreError::Corrupt {
                    path: path.clone(),
                    reason,
                })?;
            diagnostics.extend(artifact.diagnostics);
        }
        let report = ExplanationReport::new(diagnostics)?;
        fs::create_dir_all(&self.cache_dir).map_err(|source| ExplanationStoreError::Io {
            path: self.cache_dir.clone(),
            source,
        })?;
        write_json(&self.cache_dir.join(EXPLANATION_FILE), &report)
    }

    /// Expands every group whose four-character handle matches `handle`.
    pub(crate) fn explain(
        &self,
        handle: &DiagnosticGroupHandle,
    ) -> Result<Vec<ExplanationGroup>, ExplanationStoreError> {
        let path = self.cache_dir.join(EXPLANATION_FILE);
        let report: ExplanationReport = match read_json(&path) {
            Ok(report) => report,
            Err(ExplanationStoreError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                return Err(ExplanationStoreError::NoReport { path });
            }
            Err(error) => return Err(error),
        };
        report
            .validate()
            .map_err(|reason| ExplanationStoreError::Corrupt {
                path: path.clone(),
                reason,
            })?;

        let mut groups = BTreeMap::<DiagnosticGroupKey, Vec<StoredDiagnostic>>::new();
        for diagnostic in report.diagnostics {
            if diagnostic.group.handle() == *handle {
                groups
                    .entry(diagnostic.group.clone())
                    .or_default()
                    .push(diagnostic);
            }
        }
        if groups.is_empty() {
            return Err(ExplanationStoreError::NoMatch {
                handle: handle.clone(),
            });
        }
        Ok(groups
            .into_iter()
            .map(|(key, mut diagnostics)| {
                diagnostics.sort_unstable();
                ExplanationGroup { key, diagnostics }
            })
            .collect())
    }
}

#[derive(Debug)]
pub(crate) enum ExplanationStoreError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Invalid(String),
    Corrupt {
        path: PathBuf,
        reason: String,
    },
    NoReport {
        path: PathBuf,
    },
    NoMatch {
        handle: DiagnosticGroupHandle,
    },
}

impl Display for ExplanationStoreError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(formatter, "{}: {source}", path.display()),
            Self::Invalid(reason) => write!(formatter, "invalid explanation report: {reason}"),
            Self::Corrupt { path, reason } => {
                write!(
                    formatter,
                    "corrupt explanation report {}: {reason}",
                    path.display()
                )
            }
            Self::NoReport { path } => {
                write!(formatter, "no explanation report at {}", path.display())
            }
            Self::NoMatch { handle } => {
                write!(formatter, "no diagnostic group matched `{handle}`")
            }
        }
    }
}

impl std::error::Error for ExplanationStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Invalid(_)
            | Self::Corrupt { .. }
            | Self::NoReport { .. }
            | Self::NoMatch { .. } => None,
        }
    }
}

fn write_sidecar_json(
    staging_dir: &Path,
    value: &impl Serialize,
) -> Result<(), ExplanationStoreError> {
    fs::create_dir_all(staging_dir).map_err(|source| ExplanationStoreError::Io {
        path: staging_dir.to_owned(),
        source,
    })?;
    let mut sidecar = tempfile::Builder::new()
        .suffix(".partial")
        .tempfile_in(staging_dir)
        .map_err(|source| ExplanationStoreError::Io {
            path: staging_dir.to_owned(),
            source,
        })?;
    serde_json::to_writer(&mut sidecar, value).map_err(|source| {
        ExplanationStoreError::Corrupt {
            path: sidecar.path().to_owned(),
            reason: source.to_string(),
        }
    })?;
    sidecar
        .flush()
        .map_err(|source| ExplanationStoreError::Io {
            path: sidecar.path().to_owned(),
            source,
        })?;
    // Only completed sidecars have the extension consumed by `publish`.
    let completed_path = sidecar.path().with_extension("json");
    sidecar
        .persist_noclobber(&completed_path)
        .map_err(|error| ExplanationStoreError::Io {
            path: completed_path,
            source: error.error,
        })?;
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, ExplanationStoreError> {
    let source = fs::read(path).map_err(|source| ExplanationStoreError::Io {
        path: path.to_owned(),
        source,
    })?;
    serde_json::from_slice(&source).map_err(|source| ExplanationStoreError::Corrupt {
        path: path.to_owned(),
        reason: source.to_string(),
    })
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), ExplanationStoreError> {
    let parent = path.parent().ok_or_else(|| {
        ExplanationStoreError::Invalid(format!("{} has no parent directory", path.display()))
    })?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|source| ExplanationStoreError::Io {
            path: parent.to_owned(),
            source,
        })?;
    serde_json::to_writer(&mut temporary, value).map_err(|source| {
        ExplanationStoreError::Corrupt {
            path: path.to_owned(),
            reason: source.to_string(),
        }
    })?;
    temporary
        .flush()
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|source| ExplanationStoreError::Io {
            path: temporary.path().to_owned(),
            source,
        })?;
    temporary
        .persist(path)
        .map_err(|error| ExplanationStoreError::Io {
            path: path.to_owned(),
            source: error.error,
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::str::FromStr as _;

    use serde::ser::SerializeStruct as _;
    use serde::{Serialize, Serializer};

    use super::{
        ArtifactExplanation, DiagnosticGroupHandle, DiagnosticGroupKey, ExplanationStore,
        ExplanationStoreError, StoredDiagnostic, write_sidecar_json,
    };

    fn diagnostic(key: DiagnosticGroupKey, summary: &str) -> StoredDiagnostic {
        StoredDiagnostic::new(key, summary, format!("full explanation for {summary}"))
    }

    #[test]
    fn handle_is_stable_for_a_semantic_group_and_rejects_invalid_text() {
        let key = DiagnosticGroupKey::new(
            "panic-invocation",
            "sample::parse_request",
            "compiler-assert:bounds-check",
        );
        assert_eq!(key.handle().as_str(), "n5ny");
        assert_eq!(key.handle(), key.clone().handle());
        assert_eq!(key.handle().as_str().len(), 4);
        assert_eq!(
            DiagnosticGroupHandle::from_str(&key.handle().to_string()).expect("valid handle"),
            key.handle()
        );
        assert!(DiagnosticGroupHandle::from_str("oil1").is_err());
    }

    #[test]
    fn one_handle_expands_every_diagnostic_in_its_group() {
        let directory = tempfile::tempdir().expect("tempdir");
        let staging = tempfile::tempdir().expect("staging tempdir");
        let store = ExplanationStore::new(directory.path());
        let key = DiagnosticGroupKey::new("panic-invocation", "sample::parse", "");
        let first = ArtifactExplanation::new(vec![diagnostic(key.clone(), "first")])
            .expect("valid first artifact");
        let second = ArtifactExplanation::new(vec![diagnostic(key.clone(), "second")])
            .expect("valid second artifact");

        ExplanationStore::write_sidecar(staging.path(), &first).expect("write first sidecar");
        ExplanationStore::write_sidecar(staging.path(), &first).expect("write duplicate sidecar");
        ExplanationStore::write_sidecar(staging.path(), &second).expect("write second sidecar");
        store.publish(staging.path()).expect("publish report");
        let groups = store.explain(&key.handle()).expect("explain group");

        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].diagnostics().len(), 2);
        assert!(directory.path().join("explain.json").is_file());
    }

    #[test]
    fn old_explanations_require_refresh_before_native_replay() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("explain.json");
        fs::write(&path, r#"{"format-version":1,"diagnostics":[]}"#)
            .expect("old explanation report");
        let error = ExplanationStore::new(directory.path())
            .explain(&DiagnosticGroupHandle::from_str("7k3m").expect("handle"))
            .expect_err("old reports do not contain the complete rendered diagnostic");

        assert!(matches!(
            error,
            ExplanationStoreError::Corrupt { path: actual, reason }
                if actual == path && reason.contains("rerun cargo sniff-test")
        ));
    }

    #[test]
    fn a_sidecar_is_not_published_until_its_write_finishes() {
        struct ObservedArtifact<'a> {
            artifact: &'a ArtifactExplanation,
            while_writing: &'a dyn Fn(),
        }

        impl Serialize for ObservedArtifact<'_> {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut state = serializer.serialize_struct("ArtifactExplanation", 1)?;
                (self.while_writing)();
                state.serialize_field("diagnostics", &self.artifact.diagnostics)?;
                state.end()
            }
        }

        let directory = tempfile::tempdir().expect("tempdir");
        let staging = tempfile::tempdir().expect("staging tempdir");
        let store = ExplanationStore::new(directory.path());
        let key = DiagnosticGroupKey::new("panic-invocation", "sample::parse", "");
        let artifact = ArtifactExplanation::new(vec![diagnostic(key.clone(), "complete")])
            .expect("valid artifact");
        ExplanationStore::write_sidecar(staging.path(), &artifact).expect("completed sidecar");
        let next = ArtifactExplanation::new(vec![diagnostic(key.clone(), "next")])
            .expect("valid artifact");
        let during_write = || {
            store
                .publish(staging.path())
                .expect("ignore unfinished sidecar");
            let groups = store.explain(&key.handle()).expect("completed group");
            assert_eq!(groups[0].diagnostics().len(), 1);
        };
        write_sidecar_json(
            staging.path(),
            &ObservedArtifact {
                artifact: &next,
                while_writing: &during_write,
            },
        )
        .expect("finish sidecar");

        store
            .publish(staging.path())
            .expect("publish both completed sidecars");
        let groups = store.explain(&key.handle()).expect("completed group");
        assert_eq!(groups[0].diagnostics().len(), 2);
    }

    #[test]
    fn an_interrupted_temporary_sidecar_does_not_block_completed_diagnostics() {
        let directory = tempfile::tempdir().expect("tempdir");
        let staging = tempfile::tempdir().expect("staging tempdir");
        let store = ExplanationStore::new(directory.path());
        let key = DiagnosticGroupKey::new("panic-invocation", "sample::parse", "");
        let artifact = ArtifactExplanation::new(vec![diagnostic(key.clone(), "complete")])
            .expect("valid artifact");
        ExplanationStore::write_sidecar(staging.path(), &artifact).expect("completed sidecar");
        fs::write(
            staging.path().join("interrupted.partial"),
            b"{\"diagnostics\":[",
        )
        .expect("interrupted writer fixture");

        store
            .publish(staging.path())
            .expect("publish completed sidecar");

        let groups = store.explain(&key.handle()).expect("completed group");
        assert_eq!(groups[0].diagnostics().len(), 1);
    }

    #[test]
    fn a_corrupt_completed_sidecar_preserves_the_previous_report() {
        let directory = tempfile::tempdir().expect("tempdir");
        let staging = tempfile::tempdir().expect("staging tempdir");
        let store = ExplanationStore::new(directory.path());
        let key = DiagnosticGroupKey::new("panic-invocation", "sample::parse", "");
        let artifact = ArtifactExplanation::new(vec![diagnostic(key.clone(), "complete")])
            .expect("valid artifact");
        ExplanationStore::write_sidecar(staging.path(), &artifact).expect("completed sidecar");
        store
            .publish(staging.path())
            .expect("publish previous report");
        let previous = fs::read(directory.path().join("explain.json")).expect("previous report");
        let corrupt = staging.path().join("corrupt.json");
        fs::write(&corrupt, b"{\"diagnostics\":[").expect("corrupt completed sidecar");

        assert!(matches!(
            store.publish(staging.path()),
            Err(ExplanationStoreError::Corrupt { path, .. }) if path == corrupt
        ));
        assert_eq!(
            fs::read(directory.path().join("explain.json")).expect("retained report"),
            previous
        );
        assert_eq!(
            store.explain(&key.handle()).expect("previous group")[0]
                .diagnostics()
                .len(),
            1
        );
    }

    #[test]
    fn a_short_handle_collision_preserves_every_group() {
        let mut by_handle = BTreeMap::new();
        let (first, second) = (0_u32..100_000)
            .find_map(|index| {
                let key = DiagnosticGroupKey::new(
                    "panic-invocation",
                    format!("sample::function_{index}"),
                    "",
                );
                let handle = key.handle();
                by_handle
                    .insert(handle, key.clone())
                    .map(|previous| (previous, key))
            })
            .expect("the bounded search should find a 20-bit birthday collision");
        let directory = tempfile::tempdir().expect("tempdir");
        let staging = tempfile::tempdir().expect("staging tempdir");
        let store = ExplanationStore::new(directory.path());
        let artifact = ArtifactExplanation::new(vec![
            diagnostic(first.clone(), "first"),
            diagnostic(second, "second"),
        ])
        .expect("valid artifact");

        ExplanationStore::write_sidecar(staging.path(), &artifact).expect("write sidecar");
        store.publish(staging.path()).expect("publish report");

        assert_eq!(
            store
                .explain(&first.handle())
                .expect("collision groups")
                .len(),
            2
        );
    }

    #[test]
    fn publishing_an_empty_invocation_replaces_the_previous_report() {
        let directory = tempfile::tempdir().expect("tempdir");
        let first_staging = tempfile::tempdir().expect("first staging");
        let empty_staging = tempfile::tempdir().expect("empty staging");
        let store = ExplanationStore::new(directory.path());
        let key = DiagnosticGroupKey::new("panic-invocation", "sample::parse", "");
        let artifact = ArtifactExplanation::new(vec![diagnostic(key.clone(), "panic")])
            .expect("valid artifact");
        ExplanationStore::write_sidecar(first_staging.path(), &artifact).expect("write sidecar");
        store.publish(first_staging.path()).expect("publish report");

        store
            .publish(empty_staging.path())
            .expect("publish empty report");

        assert!(matches!(
            store.explain(&key.handle()),
            Err(ExplanationStoreError::NoMatch { .. })
        ));
    }
}
