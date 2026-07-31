//! On-disk analysis cache schema.
//!
//! Cache files are keyed by compiled artifact identity, not only by crate name.
//! Cargo can compile multiple versions or feature combinations of the same crate
//! name in one build, and those artifacts must not share effect evidence.
//!
//! The schema intentionally stores structured findings and trace data. Terminal
//! concerns such as colors are applied later by the reporter.

use std::collections::{BTreeMap, HashMap};
use std::fmt::{Display, Formatter};
use std::hash::Hasher as _;
use std::path::{Path, PathBuf};

use rustc_data_structures::{fingerprint::Fingerprint, stable_hasher::StableHasher};
use serde::{Deserialize, Serialize};

use crate::namespace::{StableDefPathHash, StableInstanceHash};
use crate::panics::CompilerAssertKind;
use crate::safety::SafetyOpKind;

pub const CACHE_FORMAT_VERSION: u32 = 12;
pub const CACHE_DIR_NAME: &str = "sniff-test-cache";
pub const CACHE_VERSION_DIR: &str = "v12";

/// Cached analysis for one exact rustc output artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CachedArtifactAnalysis {
    pub format_version: u32,
    pub tool_version: String,
    pub rustc_version: String,
    pub analysis_id: AnalysisId,
    pub artifact: CachedArtifactInfo,
    pub dependencies: Vec<CachedDependencyRef>,
    pub trace_arena: CachedTraceArena,
    pub finding_arena: Vec<CachedFinding>,
    pub functions: Vec<CachedFunctionSummary>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct CacheFormatHeader {
    format_version: u32,
}

impl CachedArtifactAnalysis {
    /// Canonicalizes and interns one artifact's cache contribution.
    ///
    /// # Errors
    ///
    /// Returns an error for conflicting dependency generations, duplicate
    /// function keys, or a dependency trace that cannot be resolved.
    pub fn new(
        tool_version: impl Into<String>,
        rustc_version: impl Into<String>,
        artifact: CachedArtifactInfo,
        functions: Vec<CachedFunctionInput>,
    ) -> Result<Self, CacheValidationError> {
        let functions = canonical_function_inputs(functions)?;
        let dependencies = referenced_dependencies(&functions)?;
        let dependency_ids = dependencies
            .iter()
            .enumerate()
            .map(|(index, dependency)| {
                (
                    dependency.artifact_id.clone(),
                    CachedDependencyId::new(index),
                )
            })
            .collect::<HashMap<_, _>>();
        let mut arenas = ArenaInterner::default();
        let functions = functions
            .into_iter()
            .map(|function| intern_function(function, &dependencies, &dependency_ids, &mut arenas))
            .collect::<Result<Vec<_>, _>>()?;
        let (trace_arena, finding_arena) = arenas.finish();
        let mut analysis = Self {
            format_version: CACHE_FORMAT_VERSION,
            tool_version: tool_version.into(),
            rustc_version: rustc_version.into(),
            analysis_id: AnalysisId::default(),
            artifact,
            dependencies,
            trace_arena,
            finding_arena,
            functions,
        };
        analysis.validate()?;
        analysis.analysis_id = analysis.compute_analysis_id()?;
        Ok(analysis)
    }

    #[must_use]
    pub fn dependency(&self, id: CachedDependencyId) -> Option<&CachedDependencyRef> {
        self.dependencies.get(id.index())
    }

    #[must_use]
    pub fn finding(&self, id: CachedFindingId) -> Option<&CachedFinding> {
        self.finding_arena.get(id.index())
    }

    #[must_use]
    pub fn trace(&self, id: CachedTraceId) -> Option<&CachedTrace> {
        self.trace_arena.trace(id)
    }

    #[must_use]
    pub fn trace_step(&self, id: CachedTraceStepId) -> Option<&str> {
        self.trace_arena.step(id)
    }

    /// Writes this analysis to its artifact-id path.
    ///
    /// # Errors
    ///
    /// Returns an error when the cache directories cannot be created, the
    /// analysis is invalid, cannot be serialized, or cannot be written.
    pub fn write(&self, cache_dir: &Path) -> Result<(), CacheError> {
        let artifact_path = artifact_cache_path(cache_dir, &self.artifact.artifact_id);
        self.validate()
            .map_err(|error| CacheError::invalid(&artifact_path, error))?;
        let expected_analysis_id = self
            .compute_analysis_id()
            .map_err(|error| CacheError::invalid(&artifact_path, error))?;
        if self.analysis_id != expected_analysis_id {
            return Err(CacheError::Invalid {
                path: artifact_path,
                reason: format!(
                    "analysis id {} does not match canonical content {}",
                    self.analysis_id, expected_analysis_id
                ),
            });
        }
        let source = serde_json::to_string_pretty(self).map_err(|source| CacheError::Json {
            path: artifact_path.clone(),
            source,
        })?;

        write_atomic(&artifact_path, &source)
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
        analysis
            .validate()
            .map_err(|error| CacheError::invalid(path, error))?;
        let expected_analysis_id = analysis
            .compute_analysis_id()
            .map_err(|error| CacheError::invalid(path, error))?;
        if analysis.analysis_id != expected_analysis_id {
            return Err(CacheError::Invalid {
                path: path.to_owned(),
                reason: format!(
                    "analysis id {} does not match canonical content {}",
                    analysis.analysis_id, expected_analysis_id
                ),
            });
        }
        Ok(analysis)
    }
}

/// Deterministic generation identity for one sealed artifact analysis.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AnalysisId(String);

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
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Identity and provenance for the compiled artifact represented by a cache file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CachedArtifactInfo {
    pub artifact_id: String,
    pub crate_name: String,
    pub stable_crate_id: u64,
}

/// A dependency artifact observed while analyzing this artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CachedDependencyRef {
    pub artifact_id: String,
    pub analysis_id: AnalysisId,
}

macro_rules! arena_id {
    ($name:ident) => {
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(usize);

        impl $name {
            #[must_use]
            pub const fn new(index: usize) -> Self {
                Self(index)
            }

            #[must_use]
            pub const fn index(self) -> usize {
                self.0
            }
        }
    };
}

arena_id!(CachedDependencyId);
arena_id!(CachedTraceStepId);
arena_id!(CachedTraceId);
arena_id!(CachedFindingId);

/// Cross-session key for an analyzed function or cached resume point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum CachedItemKey {
    ExactItem {
        def_path_hash: StableDefPathHash,
        instance_hash: StableInstanceHash,
    },
    GenericTemplate {
        def_path_hash: StableDefPathHash,
    },
}

impl CachedItemKey {
    #[must_use]
    pub fn exact_item(def_path_hash: StableDefPathHash, instance_hash: StableInstanceHash) -> Self {
        Self::ExactItem {
            def_path_hash,
            instance_hash,
        }
    }

    #[must_use]
    pub const fn generic_template(def_path_hash: StableDefPathHash) -> Self {
        Self::GenericTemplate { def_path_hash }
    }
}

/// Uninterned function or resume-point contribution.
#[derive(Debug, Clone)]
pub struct CachedFunctionInput {
    pub key: CachedItemKey,
    pub path: String,
    pub panic: CachedEffectInput,
    pub safety: CachedEffectInput,
}

/// Uninterned effect summary contributed before artifact arenas exist.
#[derive(Debug, Clone)]
pub struct CachedEffectInput {
    pub analysis_complete: bool,
    pub has_contract: bool,
    pub findings: Vec<CachedFindingInput>,
}

/// One uninterned finding and its local trace contribution.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct CachedFindingInput {
    #[serde(flatten)]
    pub kind: CachedFindingKind,
    pub span: String,
    pub source_span: Option<CachedSourceSpan>,
    pub trace: CachedTraceInput,
    pub reason: String,
    pub missing_requirements: Vec<CachedRequirement>,
}

/// Rendered local trace steps plus an optional exact dependency continuation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct CachedTraceInput {
    pub steps: Vec<String>,
    pub dependency_tail: Option<CachedDependencyTraceInput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct CachedDependencyTraceInput {
    pub artifact_id: String,
    pub analysis_id: AnalysisId,
    pub trace: CachedTraceId,
}

/// Cached effect facts for one analyzed report root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CachedFunctionSummary {
    pub key: CachedItemKey,
    pub path: String,
    pub panic: CachedEffectSummary,
    pub safety: CachedEffectSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CachedEffectSummary {
    pub analysis_complete: bool,
    pub has_contract: bool,
    pub findings: Vec<CachedFindingId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CachedFinding {
    #[serde(flatten)]
    pub kind: CachedFindingKind,
    pub span: String,
    pub source_span: Option<CachedSourceSpan>,
    pub trace: CachedTraceId,
    pub reason: String,
    pub missing_requirements: Vec<CachedRequirement>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CachedTraceArena {
    steps: Vec<String>,
    traces: Vec<CachedTrace>,
}

impl CachedTraceArena {
    #[must_use]
    pub fn step(&self, id: CachedTraceStepId) -> Option<&str> {
        self.steps.get(id.index()).map(String::as_str)
    }

    #[must_use]
    pub fn trace(&self, id: CachedTraceId) -> Option<&CachedTrace> {
        self.traces.get(id.index())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CachedTrace {
    pub steps: Vec<CachedTraceStepId>,
    pub dependency_tail: Option<CachedDependencyTraceRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CachedDependencyTraceRef {
    pub dependency: CachedDependencyId,
    pub trace: CachedTraceId,
}

pub type CachedRequirement = crate::contracts::ContractRequirement;

#[derive(Default)]
struct ArenaInterner {
    traces: CachedTraceArena,
    findings: Vec<CachedFinding>,
    step_ids: HashMap<String, CachedTraceStepId>,
    trace_ids: HashMap<String, CachedTraceId>,
    finding_ids: HashMap<String, CachedFindingId>,
}

impl ArenaInterner {
    fn intern_step(&mut self, step: String) -> CachedTraceStepId {
        if let Some(id) = self.step_ids.get(&step) {
            return *id;
        }
        let id = CachedTraceStepId::new(self.traces.steps.len());
        self.step_ids.insert(step.clone(), id);
        self.traces.steps.push(step);
        id
    }

    fn intern_trace(&mut self, trace: CachedTrace) -> Result<CachedTraceId, CacheValidationError> {
        let key = canonical_json(&trace)?;
        if let Some(id) = self.trace_ids.get(&key) {
            return Ok(*id);
        }
        let id = CachedTraceId::new(self.traces.traces.len());
        self.traces.traces.push(trace);
        self.trace_ids.insert(key, id);
        Ok(id)
    }

    fn intern_finding(
        &mut self,
        finding: CachedFinding,
    ) -> Result<CachedFindingId, CacheValidationError> {
        let key = canonical_json(&finding)?;
        if let Some(id) = self.finding_ids.get(&key) {
            return Ok(*id);
        }
        let id = CachedFindingId::new(self.findings.len());
        self.findings.push(finding);
        self.finding_ids.insert(key, id);
        Ok(id)
    }

    fn finish(self) -> (CachedTraceArena, Vec<CachedFinding>) {
        (self.traces, self.findings)
    }
}

fn referenced_dependencies(
    functions: &[CachedFunctionInput],
) -> Result<Vec<CachedDependencyRef>, CacheValidationError> {
    let mut canonical = BTreeMap::<String, CachedDependencyRef>::new();
    for function in functions {
        for effect in [&function.panic, &function.safety] {
            for finding in &effect.findings {
                let Some(tail) = &finding.trace.dependency_tail else {
                    continue;
                };
                let dependency = CachedDependencyRef {
                    artifact_id: tail.artifact_id.clone(),
                    analysis_id: tail.analysis_id.clone(),
                };
                match canonical.entry(dependency.artifact_id.clone()) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(dependency);
                    }
                    std::collections::btree_map::Entry::Occupied(entry)
                        if entry.get().analysis_id != dependency.analysis_id =>
                    {
                        return Err(CacheValidationError::new(format!(
                            "dependency {} has conflicting generations {} and {}",
                            dependency.artifact_id,
                            entry.get().analysis_id,
                            dependency.analysis_id
                        )));
                    }
                    std::collections::btree_map::Entry::Occupied(_) => {}
                }
            }
        }
    }
    Ok(canonical.into_values().collect())
}

fn canonical_function_inputs(
    functions: Vec<CachedFunctionInput>,
) -> Result<Vec<CachedFunctionInput>, CacheValidationError> {
    let mut canonical = BTreeMap::<CachedItemKey, CachedFunctionInput>::new();
    for function in functions {
        let key = function.key;
        if canonical.insert(key, function).is_some() {
            return Err(CacheValidationError::new(format!(
                "duplicate function item key {key:?}"
            )));
        }
    }
    Ok(canonical.into_values().collect())
}

fn intern_function(
    function: CachedFunctionInput,
    dependencies: &[CachedDependencyRef],
    dependency_ids: &HashMap<String, CachedDependencyId>,
    arenas: &mut ArenaInterner,
) -> Result<CachedFunctionSummary, CacheValidationError> {
    Ok(CachedFunctionSummary {
        key: function.key,
        path: function.path,
        panic: intern_effect(function.panic, dependencies, dependency_ids, arenas)?,
        safety: intern_effect(function.safety, dependencies, dependency_ids, arenas)?,
    })
}

fn intern_effect(
    effect: CachedEffectInput,
    dependencies: &[CachedDependencyRef],
    dependency_ids: &HashMap<String, CachedDependencyId>,
    arenas: &mut ArenaInterner,
) -> Result<CachedEffectSummary, CacheValidationError> {
    let mut finding_inputs = effect
        .findings
        .into_iter()
        .map(|finding| Ok((canonical_json(&finding)?, finding)))
        .collect::<Result<Vec<_>, CacheValidationError>>()?;
    finding_inputs.sort_by(|left, right| left.0.cmp(&right.0));
    finding_inputs.dedup_by(|left, right| left.0 == right.0);

    let mut finding_ids = Vec::new();
    for (_, input) in finding_inputs {
        let steps = input
            .trace
            .steps
            .into_iter()
            .map(|step| arenas.intern_step(step))
            .collect();
        let dependency_tail = input
            .trace
            .dependency_tail
            .map(|tail| {
                let dependency =
                    dependency_ids
                        .get(&tail.artifact_id)
                        .copied()
                        .ok_or_else(|| {
                            CacheValidationError::new(format!(
                                "trace references unknown dependency {}",
                                tail.artifact_id
                            ))
                        })?;
                let dependency_generation = &dependencies[dependency.index()].analysis_id;
                if dependency_generation != &tail.analysis_id {
                    return Err(CacheValidationError::new(format!(
                        "trace generation {} does not match dependency {} generation {}",
                        tail.analysis_id, tail.artifact_id, dependency_generation
                    )));
                }
                Ok(CachedDependencyTraceRef {
                    dependency,
                    trace: tail.trace,
                })
            })
            .transpose()?;
        let trace = arenas.intern_trace(CachedTrace {
            steps,
            dependency_tail,
        })?;
        let finding = arenas.intern_finding(CachedFinding {
            kind: input.kind,
            span: input.span,
            source_span: input.source_span,
            trace,
            reason: input.reason,
            missing_requirements: input.missing_requirements,
        })?;
        finding_ids.push(finding);
    }
    finding_ids.sort();
    finding_ids.dedup();
    Ok(CachedEffectSummary {
        analysis_complete: effect.analysis_complete,
        has_contract: effect.has_contract,
        findings: finding_ids,
    })
}

fn canonical_json(value: &impl Serialize) -> Result<String, CacheValidationError> {
    serde_json::to_string(value).map_err(|error| {
        CacheValidationError::new(format!("cannot canonicalize cache data: {error}"))
    })
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

/// Semantic category for cached evidence.
///
/// The reporter maps these categories to labels, counts, and colors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case",
    tag = "kind",
    deny_unknown_fields
)]
pub enum CachedFindingKind {
    CompilerAssert {
        compiler_assert_kind: CompilerAssertKind,
    },
    PanicInvocation {},
    PanicObligation {},
    TrustedPanicObligation {},
    IndirectCallBoundary {},
    UnsafeCallMissingJustification {},
    UnsafeCallMissingRequirements {},
    UnsafeOpMissingJustification {
        safety_op_kind: SafetyOpKind,
    },
    SafetyObligationMissingJustification {},
    SafetyObligationMissingRequirements {},
}

impl CachedFindingKind {
    pub(crate) fn is_panic(self) -> bool {
        matches!(
            self,
            Self::CompilerAssert { .. }
                | Self::PanicInvocation {}
                | Self::PanicObligation {}
                | Self::TrustedPanicObligation {}
                | Self::IndirectCallBoundary {}
        )
    }

    #[must_use]
    pub(crate) const fn compiler_assert_kind(self) -> Option<CompilerAssertKind> {
        match self {
            Self::CompilerAssert {
                compiler_assert_kind,
            } => Some(compiler_assert_kind),
            _ => None,
        }
    }
}

impl CachedArtifactAnalysis {
    fn validate(&self) -> Result<(), CacheValidationError> {
        if self.format_version != CACHE_FORMAT_VERSION {
            return Err(CacheValidationError::new(format!(
                "analysis declares cache format {}, expected {}",
                self.format_version, CACHE_FORMAT_VERSION
            )));
        }
        validate_dependencies(&self.artifact, &self.dependencies)?;
        validate_traces(&self.trace_arena, &self.dependencies)?;
        validate_findings(&self.finding_arena, &self.trace_arena)?;
        validate_functions(
            &self.functions,
            &self.finding_arena,
            self.artifact.stable_crate_id,
        )?;
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

fn validate_dependencies(
    artifact: &CachedArtifactInfo,
    dependencies: &[CachedDependencyRef],
) -> Result<(), CacheValidationError> {
    for pair in dependencies.windows(2) {
        if pair[0].artifact_id >= pair[1].artifact_id {
            return Err(CacheValidationError::new(
                "dependencies must be uniquely sorted by artifact id",
            ));
        }
    }
    for dependency in dependencies {
        if dependency.artifact_id == artifact.artifact_id {
            return Err(CacheValidationError::new(format!(
                "artifact {} cannot depend on its own analysis",
                artifact.artifact_id
            )));
        }
        if dependency.analysis_id.0.is_empty() {
            return Err(CacheValidationError::new(format!(
                "dependency {} has an empty analysis generation",
                dependency.artifact_id
            )));
        }
    }
    Ok(())
}

fn validate_traces(
    arena: &CachedTraceArena,
    dependencies: &[CachedDependencyRef],
) -> Result<(), CacheValidationError> {
    for (index, trace) in arena.traces.iter().enumerate() {
        for step in &trace.steps {
            if arena.step(*step).is_none() {
                return Err(CacheValidationError::new(format!(
                    "trace {index} references missing trace step {}",
                    step.index()
                )));
            }
        }
        if let Some(tail) = &trace.dependency_tail
            && dependencies.get(tail.dependency.index()).is_none()
        {
            return Err(CacheValidationError::new(format!(
                "trace {index} references missing dependency {}",
                tail.dependency.index()
            )));
        }
    }
    Ok(())
}

fn validate_findings(
    findings: &[CachedFinding],
    traces: &CachedTraceArena,
) -> Result<(), CacheValidationError> {
    for (index, finding) in findings.iter().enumerate() {
        if traces.trace(finding.trace).is_none() {
            return Err(CacheValidationError::new(format!(
                "finding {index} references missing trace {}",
                finding.trace.index()
            )));
        }
    }
    Ok(())
}

fn validate_functions(
    functions: &[CachedFunctionSummary],
    findings: &[CachedFinding],
    stable_crate_id: u64,
) -> Result<(), CacheValidationError> {
    for pair in functions.windows(2) {
        if pair[0].key >= pair[1].key {
            return Err(CacheValidationError::new(
                "function entries must be uniquely sorted by item key",
            ));
        }
    }
    for (index, function) in functions.iter().enumerate() {
        let function_stable_crate_id = match function.key {
            CachedItemKey::ExactItem { def_path_hash, .. }
            | CachedItemKey::GenericTemplate { def_path_hash } => def_path_hash.stable_crate_id(),
        };
        if function_stable_crate_id != stable_crate_id {
            return Err(CacheValidationError::new(format!(
                "function {index} does not belong to artifact stable crate id {stable_crate_id:016x}"
            )));
        }
        for (effect_name, effect) in [("panic", &function.panic), ("safety", &function.safety)] {
            if effect.findings.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(CacheValidationError::new(format!(
                    "function {index} {effect_name} findings must be uniquely sorted"
                )));
            }
            for finding in &effect.findings {
                let Some(finding) = findings.get(finding.index()) else {
                    return Err(CacheValidationError::new(format!(
                        "function {index} references missing {effect_name} finding {}",
                        finding.index()
                    )));
                };
                if finding.kind.is_panic() != (effect_name == "panic") {
                    return Err(CacheValidationError::new(format!(
                        "function {index} {effect_name} summary references a mismatched finding kind"
                    )));
                }
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheValidationError {
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
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        self.reason.fmt(formatter)
    }
}

impl std::error::Error for CacheValidationError {}

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
            Self::Invalid { path, reason } => {
                write!(f, "invalid cache {}: {reason}", path.display())
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
pub fn artifact_cache_path(cache_dir: &Path, artifact_id: &str) -> PathBuf {
    cache_dir
        .join("artifacts")
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
        AnalysisId, CacheError, CacheExpectations, CachedArtifactAnalysis, CachedArtifactInfo,
        CachedDependencyTraceInput, CachedEffectInput, CachedFinding, CachedFindingInput,
        CachedFindingKind, CachedFunctionInput, CachedItemKey, CachedTraceId, CachedTraceInput,
        artifact_cache_path, artifact_id_from_extern_path, default_cache_dir, write_atomic,
    };
    use crate::panics::CompilerAssertKind;
    use crate::safety::SafetyOpKind;

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
            "/target/plugin-nightly/sniff-test-cache/v12/artifacts/sniff_test-29f0.json"
        );
    }

    #[test]
    fn construction_derives_dependencies_and_canonicalizes_arenas() {
        let generation = AnalysisId::from("dependency-generation");
        let dependency_finding = |reason| {
            let mut finding = finding_input(reason);
            finding.trace.dependency_tail = Some(CachedDependencyTraceInput {
                artifact_id: String::from("dep-aaaa"),
                analysis_id: generation.clone(),
                trace: CachedTraceId::new(7),
            });
            finding
        };
        let first = analysis_with_input(vec![
            function_input(
                generic_key(2),
                "demo::generic",
                vec![dependency_finding("second")],
            ),
            function_input(
                exact_key(1, 11),
                "demo::exact",
                vec![dependency_finding("first")],
            ),
        ]);
        let second = analysis_with_input(vec![
            function_input(
                exact_key(1, 11),
                "demo::exact",
                vec![dependency_finding("first")],
            ),
            function_input(
                generic_key(2),
                "demo::generic",
                vec![dependency_finding("second")],
            ),
        ]);

        assert_eq!(first, second);
        assert_eq!(
            serde_json::to_string(&first).expect("serialize"),
            serde_json::to_string(&second).expect("serialize")
        );
        assert_eq!(first.dependencies.len(), 1);
        assert_eq!(first.dependencies[0].artifact_id, "dep-aaaa");
        assert_eq!(first.dependencies[0].analysis_id, generation);
        assert_eq!(first.trace_arena.steps.len(), 1);
        assert_eq!(first.trace_arena.traces.len(), 1);
        assert_eq!(first.finding_arena.len(), 2);
    }

    #[test]
    fn construction_preserves_and_serializes_typed_finding_subtypes() {
        let compiler_assert = CachedFindingInput {
            kind: CachedFindingKind::CompilerAssert {
                compiler_assert_kind: CompilerAssertKind::BoundsCheck,
            },
            ..finding_input("bounds check")
        };
        let safety_op = CachedFindingInput {
            kind: CachedFindingKind::UnsafeOpMissingJustification {
                safety_op_kind: SafetyOpKind::DerefRawPointer,
            },
            ..finding_input("raw pointer dereference")
        };
        let analysis = analysis_with_input(vec![CachedFunctionInput {
            key: exact_key(7, 77),
            path: String::from("demo::typed"),
            panic: effect_input(vec![compiler_assert]),
            safety: effect_input(vec![safety_op]),
        }]);

        let compiler_assert = analysis
            .finding_arena
            .iter()
            .find(|finding| {
                matches!(
                    finding.kind,
                    CachedFindingKind::CompilerAssert {
                        compiler_assert_kind: CompilerAssertKind::BoundsCheck
                    }
                )
            })
            .expect("compiler assert");
        assert_eq!(
            compiler_assert.kind.compiler_assert_kind(),
            Some(CompilerAssertKind::BoundsCheck)
        );

        let safety_op = analysis
            .finding_arena
            .iter()
            .find(|finding| {
                matches!(
                    finding.kind,
                    CachedFindingKind::UnsafeOpMissingJustification {
                        safety_op_kind: SafetyOpKind::DerefRawPointer
                    }
                )
            })
            .expect("safety op");
        assert_eq!(safety_op.kind.compiler_assert_kind(), None);

        let json = serde_json::to_value(&analysis).expect("serialize");
        let findings = json["finding-arena"].as_array().expect("finding arena");
        assert!(findings.iter().any(|finding| {
            finding["compiler-assert-kind"] == "bounds-check"
                && finding.get("safety-op-kind").is_none()
        }));
        assert!(findings.iter().any(|finding| {
            finding["safety-op-kind"] == "raw-pointer-dereference"
                && finding.get("compiler-assert-kind").is_none()
        }));

        let dir = tempfile::tempdir().expect("temp dir");
        let path = artifact_cache_path(dir.path(), &analysis.artifact.artifact_id);
        analysis.write(dir.path()).expect("write");
        let loaded =
            CachedArtifactAnalysis::read(&path, &expectations()).expect("read typed findings");
        assert_eq!(loaded, analysis);
    }

    #[test]
    fn cached_finding_subtypes_are_required_and_exclusive_when_deserializing() {
        let missing_compiler_assert_subtype = cached_finding_json("compiler-assert");
        let mut misplaced_compiler_assert_subtype = cached_finding_json("panic-invocation");
        misplaced_compiler_assert_subtype["compiler-assert-kind"] =
            serde_json::json!("bounds-check");
        let missing_safety_op_subtype = cached_finding_json("unsafe-op-missing-justification");
        let mut misplaced_safety_op_subtype =
            cached_finding_json("unsafe-call-missing-justification");
        misplaced_safety_op_subtype["safety-op-kind"] =
            serde_json::json!("raw-pointer-dereference");

        for (case, finding) in [
            (
                "compiler assert without subtype",
                missing_compiler_assert_subtype,
            ),
            (
                "compiler assert subtype on panic invocation",
                misplaced_compiler_assert_subtype,
            ),
            (
                "unsafe operation without subtype",
                missing_safety_op_subtype,
            ),
            (
                "safety operation subtype on unsafe call",
                misplaced_safety_op_subtype,
            ),
        ] {
            assert!(
                serde_json::from_value::<CachedFinding>(finding).is_err(),
                "{case}"
            );
        }
    }

    #[test]
    fn exact_instances_and_generic_templates_are_distinct_resume_points() {
        let exact = exact_key(3, 33);
        let generic = generic_key(3);
        let analysis = analysis_with_input(vec![
            function_input(generic, "demo::generic", Vec::new()),
            function_input(exact, "demo::generic::<u32>", Vec::new()),
        ]);

        assert_eq!(
            analysis
                .functions
                .iter()
                .find(|function| function.key == exact)
                .map(|function| function.path.as_str()),
            Some("demo::generic::<u32>")
        );
        assert_eq!(
            analysis
                .functions
                .iter()
                .find(|function| function.key == generic)
                .map(|function| function.path.as_str()),
            Some("demo::generic")
        );
    }

    #[test]
    fn dependency_trace_tails_retain_exact_dependency_and_foreign_trace() {
        let generation = AnalysisId::from("dependency-generation");
        let foreign_trace = CachedTraceId::new(7);
        let mut finding = finding_input("dependency finding");
        finding.trace.dependency_tail = Some(CachedDependencyTraceInput {
            artifact_id: String::from("dep-aaaa"),
            analysis_id: generation.clone(),
            trace: foreign_trace,
        });
        let analysis = analysis_with_input(vec![function_input(
            exact_key(4, 44),
            "demo::root",
            vec![finding],
        )]);
        let trace = analysis.trace(first_trace(&analysis)).expect("local trace");
        let tail = trace.dependency_tail.as_ref().expect("dependency tail");

        assert_eq!(
            analysis
                .dependency(tail.dependency)
                .map(|dependency| dependency.artifact_id.as_str()),
            Some("dep-aaaa")
        );
        assert_eq!(tail.trace, foreign_trace);
    }

    #[test]
    fn construction_rejects_duplicate_function_keys() {
        let key = exact_key(3, 33);
        let error = CachedArtifactAnalysis::new(
            "0.1.0",
            "rustc 1.97.0-nightly",
            CachedArtifactInfo {
                artifact_id: String::from("dep-1234"),
                crate_name: String::from("dep"),
                stable_crate_id: 1,
            },
            vec![
                function_input(key, "demo::root", Vec::new()),
                function_input(key, "demo::root", Vec::new()),
            ],
        )
        .expect_err("duplicate key");

        assert!(error.to_string().contains("duplicate function item key"));
    }

    #[test]
    fn complete_clean_function_entries_survive_round_trip() {
        let analysis = analysis_with_input(vec![function_input(
            exact_key(3, 33),
            "demo::clean",
            Vec::new(),
        )]);
        let dir = tempfile::tempdir().expect("temp dir");
        let path = artifact_cache_path(dir.path(), &analysis.artifact.artifact_id);

        analysis.write(dir.path()).expect("write");
        let loaded =
            CachedArtifactAnalysis::read(&path, &expectations()).expect("read clean summary");
        let key = exact_key(3, 33);
        let function = loaded
            .functions
            .iter()
            .find(|function| function.key == key)
            .expect("clean function");

        assert!(function.panic.analysis_complete);
        assert!(function.panic.findings.is_empty());
        assert!(function.safety.analysis_complete);
        assert!(function.safety.findings.is_empty());
    }

    #[test]
    fn cache_reads_reject_invalid_local_indices() {
        let mut analysis = analysis_with_finding();
        let function = analysis.functions.first_mut().expect("function");
        function.panic.findings = vec![super::CachedFindingId::new(99)];
        analysis.analysis_id = analysis.compute_analysis_id().expect("fingerprint");
        let (dir, path) = write_raw(&analysis);

        assert!(matches!(
            CachedArtifactAnalysis::read(&path, &expectations()),
            Err(CacheError::Invalid { reason, .. })
                if reason.contains("finding 99")
        ));
        drop(dir);
    }

    #[test]
    fn cache_reads_reject_findings_in_the_wrong_effect_summary() {
        let mut analysis = analysis_with_finding();
        analysis.finding_arena[0].kind = CachedFindingKind::UnsafeCallMissingJustification {};
        analysis.analysis_id = analysis.compute_analysis_id().expect("fingerprint");
        let (dir, path) = write_raw(&analysis);

        assert!(matches!(
            CachedArtifactAnalysis::read(&path, &expectations()),
            Err(CacheError::Invalid { reason, .. })
                if reason.contains("mismatched finding kind")
        ));
        drop(dir);
    }

    #[test]
    fn cache_reads_reject_invalid_trace_step_indices() {
        let mut analysis = analysis_with_finding();
        analysis.trace_arena.traces[0].steps = vec![super::CachedTraceStepId::new(99)];
        analysis.analysis_id = analysis.compute_analysis_id().expect("fingerprint");
        let (dir, path) = write_raw(&analysis);

        assert!(matches!(
            CachedArtifactAnalysis::read(&path, &expectations()),
            Err(CacheError::Invalid { reason, .. })
                if reason.contains("trace step 99")
        ));
        drop(dir);
    }

    #[test]
    fn cache_reads_reject_self_dependency_cycles() {
        let mut finding = finding_input("self dependency");
        finding.trace.dependency_tail = Some(CachedDependencyTraceInput {
            artifact_id: String::from("other-artifact"),
            analysis_id: AnalysisId::from("other-generation"),
            trace: CachedTraceId::new(0),
        });
        let mut analysis = analysis_with_input(vec![function_input(
            exact_key(6, 66),
            "demo::self_cycle",
            vec![finding],
        )]);
        analysis.dependencies[0].artifact_id = analysis.artifact.artifact_id.clone();
        analysis.analysis_id = analysis.compute_analysis_id().expect("fingerprint");
        let (dir, path) = write_raw(&analysis);

        assert!(matches!(
            CachedArtifactAnalysis::read(&path, &expectations()),
            Err(CacheError::Invalid { reason, .. })
                if reason.contains("own analysis")
        ));
        drop(dir);
    }

    #[test]
    fn construction_rejects_conflicting_dependency_generations() {
        let mut stale = finding_input("stale dependency finding");
        stale.trace.dependency_tail = Some(CachedDependencyTraceInput {
            artifact_id: String::from("dep-aaaa"),
            analysis_id: AnalysisId::from("stale-generation"),
            trace: CachedTraceId::new(7),
        });
        let mut current = finding_input("current dependency finding");
        current.trace.dependency_tail = Some(CachedDependencyTraceInput {
            artifact_id: String::from("dep-aaaa"),
            analysis_id: AnalysisId::from("current-generation"),
            trace: CachedTraceId::new(8),
        });
        let error = CachedArtifactAnalysis::new(
            "0.1.0",
            "rustc 1.97.0-nightly",
            CachedArtifactInfo {
                artifact_id: String::from("dep-1234"),
                crate_name: String::from("dep"),
                stable_crate_id: 1,
            },
            vec![function_input(
                exact_key(4, 44),
                "demo::root",
                vec![stale, current],
            )],
        )
        .expect_err("conflicting generations");

        assert!(error.to_string().contains("conflicting generations"));
    }

    #[test]
    fn cache_writes_only_the_artifact_file() {
        let analysis = analysis_with_input(Vec::new());
        let dir = tempfile::tempdir().expect("temp dir");

        analysis.write(dir.path()).expect("write");

        assert!(artifact_cache_path(dir.path(), "dep-1234").is_file());
        assert!(!dir.path().join("crates").exists());
        assert_eq!(files_below(dir.path()), 1);
    }

    #[test]
    fn cache_reads_reject_other_tool_rustc_format_and_analysis_versions() {
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

        let mut stale_generation = good;
        stale_generation.analysis_id = AnalysisId::from("stale-generation");
        write(&stale_generation);
        assert!(matches!(
            CachedArtifactAnalysis::read(&path, &current),
            Err(CacheError::Invalid { reason, .. })
                if reason.contains("analysis id")
        ));
    }

    fn analysis(tool_version: &str, rustc_version: &str) -> CachedArtifactAnalysis {
        CachedArtifactAnalysis::new(
            tool_version,
            rustc_version,
            CachedArtifactInfo {
                artifact_id: String::from("dep-1234"),
                crate_name: String::from("dep"),
                stable_crate_id: 1,
            },
            Vec::new(),
        )
        .expect("valid analysis")
    }

    fn analysis_with_input(functions: Vec<CachedFunctionInput>) -> CachedArtifactAnalysis {
        CachedArtifactAnalysis::new(
            "0.1.0",
            "rustc 1.97.0-nightly",
            CachedArtifactInfo {
                artifact_id: String::from("dep-1234"),
                crate_name: String::from("dep"),
                stable_crate_id: 1,
            },
            functions,
        )
        .expect("valid analysis")
    }

    fn analysis_with_finding() -> CachedArtifactAnalysis {
        analysis_with_input(vec![function_input(
            exact_key(5, 55),
            "demo::root",
            vec![finding_input("panic")],
        )])
    }

    fn function_input(
        key: CachedItemKey,
        path: &str,
        findings: Vec<CachedFindingInput>,
    ) -> CachedFunctionInput {
        CachedFunctionInput {
            key,
            path: path.to_owned(),
            panic: effect_input(findings),
            safety: effect_input(Vec::new()),
        }
    }

    fn effect_input(findings: Vec<CachedFindingInput>) -> CachedEffectInput {
        CachedEffectInput {
            analysis_complete: true,
            has_contract: false,
            findings,
        }
    }

    fn finding_input(reason: &str) -> CachedFindingInput {
        CachedFindingInput {
            kind: CachedFindingKind::PanicInvocation {},
            span: String::from("src/lib.rs:1:1"),
            source_span: None,
            trace: CachedTraceInput {
                steps: vec![String::from(
                    "src/lib.rs:1:1: demo::root --direct-call-> core::panicking::panic",
                )],
                dependency_tail: None,
            },
            reason: reason.to_owned(),
            missing_requirements: Vec::new(),
        }
    }

    fn cached_finding_json(kind: &str) -> serde_json::Value {
        serde_json::json!({
            "kind": kind,
            "span": "src/lib.rs:1:1",
            "source-span": null,
            "trace": 0,
            "reason": "test finding",
            "missing-requirements": [],
        })
    }

    fn first_trace(analysis: &CachedArtifactAnalysis) -> CachedTraceId {
        let function = analysis.functions.first().expect("function");
        let finding = analysis
            .finding(function.panic.findings[0])
            .expect("finding");
        finding.trace
    }

    fn exact_key(definition: u128, instance: u128) -> CachedItemKey {
        CachedItemKey::exact_item(def_path_hash(definition), instance_hash(instance))
    }

    fn generic_key(definition: u128) -> CachedItemKey {
        CachedItemKey::generic_template(def_path_hash(definition))
    }

    fn def_path_hash(value: u128) -> crate::namespace::StableDefPathHash {
        serde_json::from_str(&format!("\"{:016x}{value:016x}\"", 1_u64)).expect("def path hash")
    }

    fn instance_hash(value: u128) -> crate::namespace::StableInstanceHash {
        serde_json::from_str(&format!("\"{value:032x}\"")).expect("instance hash")
    }

    fn expectations() -> CacheExpectations<'static> {
        CacheExpectations {
            tool_version: "0.1.0",
            rustc_version: "rustc 1.97.0-nightly",
        }
    }

    fn write_raw(analysis: &CachedArtifactAnalysis) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = artifact_cache_path(dir.path(), &analysis.artifact.artifact_id);
        write_atomic(
            &path,
            &serde_json::to_string_pretty(analysis).expect("serialize"),
        )
        .expect("write");
        (dir, path)
    }

    fn files_below(path: &std::path::Path) -> usize {
        std::fs::read_dir(path)
            .expect("read directory")
            .map(|entry| entry.expect("directory entry").path())
            .map(|path| if path.is_dir() { files_below(&path) } else { 1 })
            .sum()
    }
}
