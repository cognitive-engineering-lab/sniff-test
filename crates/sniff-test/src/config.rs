//! Configuration parsing and matching.
//!
//! The public config stores user-facing TOML values. Namespace and function
//! patterns are compiled during parsing so MIR traversal can query policy
//! without rebuilding matchers for every edge.
//!
//! Path patterns treat `::` as a separator. For example, `std` matches only
//! the crate namespace root, `std::*` matches one segment under `std`, and
//! `std::**` matches `std` and everything beneath it. Definitions are matched
//! against their stable namespace forms (crate root, definition-site path, and
//! impl self-type path) plus rustc's session-rendered display path; see
//! [`crate::namespace::namespace_candidates`]. Thus `alloc::**` also covers
//! trait-impl methods such as `<Vec<T> as Index<usize>>::index`. Use Rust crate
//! names in patterns, such as `proc_macro2`, not package names like
//! `proc-macro2`.

use std::collections::BTreeMap;
use std::fmt::{Debug, Display, Formatter};
use std::ops::Range;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use toml::Spanned;

use crate::contracts::ContractDocOverrides;
use crate::path_patterns::PathPatterns;

pub const DEFAULT_MANIFEST_FILE: &str = "sniff-test.toml";
pub const EXAMPLE_MANIFEST: &str = include_str!("../example-manifest.toml");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SniffTestConfig {
    pub compiler: CompilerConfig,
    pub analysis: AnalysisConfig,
    pub contracts: ContractsConfig,
    pub effects: BTreeMap<String, EffectConfig>,
    pub warnings: Vec<ConfigWarning>,
}

impl Default for SniffTestConfig {
    fn default() -> Self {
        Self {
            compiler: CompilerConfig::default(),
            analysis: AnalysisConfig::default(),
            contracts: ContractsConfig::default(),
            effects: crate::effects::registered_effect_configs(),
            warnings: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigWarning {
    pub field: String,
    pub message: String,
}

#[derive(Deserialize, Default)]
struct RawSniffTestConfig {
    #[serde(default)]
    compiler: CompilerConfig,
    #[serde(default)]
    analysis: AnalysisConfig,
    #[serde(default)]
    contracts: ContractsConfig,
    #[serde(flatten)]
    effects: BTreeMap<String, RawEffectConfig>,
}

impl<'de> Deserialize<'de> for SniffTestConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawSniffTestConfig::deserialize(deserializer)?;
        let mut config = Self::default();
        config.compiler = raw.compiler;
        config.analysis = raw.analysis;
        config.contracts = raw.contracts;
        for (name, effect) in raw.effects {
            let Some(default) = config.effects.get_mut(&name) else {
                return Err(serde::de::Error::custom(format!(
                    "unknown effect section `{name}`"
                )));
            };
            effect.apply(&name, default, &mut config.warnings);
        }
        Ok(config)
    }
}

impl SniffTestConfig {
    #[must_use]
    pub fn effect(&self, name: &str) -> &EffectConfig {
        self.effects
            .get(name)
            .unwrap_or_else(|| panic!("unregistered effect `{name}`"))
    }

    #[must_use]
    #[cfg(test)]
    pub fn effect_mut(&mut self, name: &str) -> &mut EffectConfig {
        self.effects
            .get_mut(name)
            .unwrap_or_else(|| panic!("unregistered effect `{name}`"))
    }

    /// Loads a sniff-test manifest from disk.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read or when the manifest contains unsupported
    /// syntax.
    pub fn from_manifest_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let source = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_owned(),
            source,
        })?;
        let mut config = Self::from_manifest_str(&source).map_err(|source| ConfigError::Parse {
            path: path.to_owned(),
            source,
        })?;
        let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
        config.contracts.load_overrides(base_dir)?;
        Ok(config)
    }

    /// Parses a sniff-test manifest from a string.
    ///
    /// # Errors
    ///
    /// Returns an error when the manifest contains unsupported syntax.
    pub fn from_manifest_str(source: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(source)
    }

    pub(crate) fn emit_warnings(&self, path: &Path) {
        for warning in &self.warnings {
            eprintln!(
                "warning: {}: {}: {}",
                path.display(),
                warning.field,
                warning.message
            );
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
#[serde(default)]
pub struct CompilerConfig {
    /// Whether rustc should emit integer overflow and invalid-shift checks.
    pub overflow_checks: OverflowChecks,
    /// Whether rustc should perform MIR inlining before analysis.
    pub inline_mir: MirInlining,
}

impl Default for CompilerConfig {
    fn default() -> Self {
        Self {
            overflow_checks: OverflowChecks::Profile,
            inline_mir: MirInlining::Off,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
#[serde(default)]
pub struct AnalysisConfig {
    /// Whether detailed reports include every edge in the triggering trace.
    pub show_full_stack_trace: bool,
    /// Current-crate functions selected as report roots.
    pub report_roots: Spanned<ReportRootSet>,
    /// How `// PANIC:` and `// SAFETY:` comments are found for spans produced
    /// by macro expansion.
    pub marker_probing: MarkerProbing,
    /// How call-site comments are matched against documented effect
    /// obligations.
    pub effect_doc_matching: EffectDocMatching,
    /// User-facing severity for analyzer-wide finding classes.
    pub lints: AnalysisLintConfig,
    /// Maximum number of invocation or transparent-body edges followed from
    /// one effect source.
    pub max_trace_depth: usize,
    /// Distinct `(origin, function, state)` budget for one effect trace.
    pub trace_state_budget: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
#[serde(default)]
pub struct ContractsConfig {
    /// TOML files containing synthetic rustdoc markdown by namespace glob.
    pub override_files: Vec<PathBuf>,
    #[serde(skip)]
    pub overrides: ContractDocOverrides,
    #[serde(skip)]
    resolved_override_files: Vec<PathBuf>,
}

impl ContractsConfig {
    #[must_use]
    pub fn resolved_override_files(&self) -> &[PathBuf] {
        &self.resolved_override_files
    }

    fn load_overrides(&mut self, base_dir: &Path) -> Result<(), ConfigError> {
        let mut entries = Vec::new();
        let mut resolved_files = Vec::new();
        for path in &self.override_files {
            let path = if path.is_absolute() {
                path.clone()
            } else {
                base_dir.join(path)
            };
            let source =
                std::fs::read_to_string(&path).map_err(|source| ConfigError::OverrideIo {
                    path: path.clone(),
                    source,
                })?;
            let override_file =
                toml::from_str::<ContractDocOverrideFile>(&source).map_err(|source| {
                    ConfigError::OverrideParse {
                        path: path.clone(),
                        source,
                    }
                })?;
            let file_entries = override_file
                .overrides
                .into_iter()
                .map(|(pattern, markdown)| (pattern, normalize_override_markdown(&markdown)))
                .collect::<Vec<_>>();
            ContractDocOverrides::new(file_entries.clone()).map_err(|source| {
                ConfigError::OverrideGlob {
                    path: path.clone(),
                    source,
                }
            })?;
            entries.extend(file_entries);
            resolved_files.push(path);
        }

        self.overrides =
            ContractDocOverrides::new(entries).expect("override globs were validated per file");
        self.resolved_override_files = resolved_files;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContractDocOverrideFile {
    overrides: BTreeMap<String, String>,
}

fn normalize_override_markdown(markdown: &str) -> String {
    let lines = markdown.lines().collect::<Vec<_>>();
    let first_nonblank = lines
        .iter()
        .position(|line| !line.trim().is_empty())
        .unwrap_or(0);
    let last_nonblank = lines
        .iter()
        .rposition(|line| !line.trim().is_empty())
        .unwrap_or(first_nonblank);
    let lines = &lines[first_nonblank..=last_nonblank];
    let indent = lines
        .iter()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.len() - line.trim_start().len())
        .min()
        .unwrap_or(0);
    lines
        .iter()
        .map(|line| line.get(indent..).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            show_full_stack_trace: false,
            report_roots: Spanned::new(0..0, ReportRootSet::Public),
            marker_probing: MarkerProbing::MacroDefinitionFirst,
            effect_doc_matching: EffectDocMatching::AnyJustification,
            lints: AnalysisLintConfig::default(),
            max_trace_depth: 256,
            trace_state_budget: 1_000_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EffectDocMatching {
    /// Any nonempty justification discharges the complete documented effect
    /// contract, regardless of its requirement names or list structure.
    #[default]
    AnyJustification,
    /// Each documented requirement must have a corresponding justification,
    /// matched by name or anonymous list structure.
    Exact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MarkerProbing {
    /// Probe the final user callsite only.
    SourceCallsite,
    /// Probe macro definition spans first, then macro callsites outward, then
    /// the final user callsite.
    #[default]
    MacroDefinitionFirst,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct AnalysisLintConfig {
    pub undocumented_effect_invocation: LintLevel,
}

impl Default for AnalysisLintConfig {
    fn default() -> Self {
        Self {
            undocumented_effect_invocation: LintLevel::Warn,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum OverflowChecks {
    /// Respect the selected Cargo/rustc profile.
    #[default]
    Profile,
    /// Force `-C overflow-checks=yes`.
    On,
    /// Force `-C overflow-checks=no`.
    Off,
}

impl OverflowChecks {
    #[must_use]
    pub fn rustc_flag(self) -> Option<&'static str> {
        match self {
            Self::Profile => None,
            Self::On => Some("overflow-checks=yes"),
            Self::Off => Some("overflow-checks=no"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MirInlining {
    /// Respect rustc's selected behavior.
    Profile,
    /// Force `-Z inline-mir=yes`.
    On,
    /// Force `-Z inline-mir=no` and disable MIR inline passes.
    #[default]
    Off,
}

impl MirInlining {
    #[must_use]
    pub fn rustc_flags(self) -> &'static [&'static str] {
        match self {
            Self::Profile => &[],
            Self::On => &["inline-mir=yes"],
            Self::Off => &[
                "inline-mir=no",
                "inline-mir-threshold=0",
                "inline-mir-forwarder-threshold=0",
                "inline-mir-hint-threshold=0",
                "mir-enable-passes=-Inline,-ForceInline",
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectConfig {
    pub ignored_namespaces: PathPatterns,
    pub trusted_boundary_namespaces: PathPatterns,
    pub lints: EffectLintConfig,
    pub coverage: CoverageConfig,
}

impl Default for EffectConfig {
    fn default() -> Self {
        Self {
            ignored_namespaces: PathPatterns::default(),
            trusted_boundary_namespaces: PathPatterns::default(),
            lints: EffectLintConfig::default(),
            coverage: CoverageConfig::default(),
        }
    }
}

impl EffectConfig {
    #[must_use]
    pub fn builder() -> EffectConfigBuilder {
        EffectConfigBuilder::default()
    }

    #[must_use]
    pub(crate) fn ignored_namespaces(&self) -> &PathPatterns {
        &self.ignored_namespaces
    }

    #[must_use]
    pub(crate) fn trusted_boundary_namespaces(&self) -> &PathPatterns {
        &self.trusted_boundary_namespaces
    }

    #[must_use]
    pub(crate) fn finding_lints(&self) -> EffectFindingLints {
        EffectFindingLints {
            concrete_invocation: self.lints.invocation,
            ambiguous_marker: self.lints.ambiguous_marker,
            ambiguous_requirement: self.lints.ambiguous_requirement,
        }
    }

    #[must_use]
    pub(crate) fn operation_lint(&self, operation: Option<&str>) -> LintLevel {
        operation
            .and_then(|kind| self.lints.operations.get(kind))
            .copied()
            .unwrap_or(self.lints.operation)
    }

    #[must_use]
    pub(crate) fn effective_coverage(&self) -> EffectiveCoverageConfig {
        EffectiveCoverageConfig {
            unresolved_call_target: self.coverage.unresolved_call_target,
            analysis_incomplete: self.coverage.analysis_incomplete,
        }
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) fn ignores_candidates(&self, candidates: &[String]) -> bool {
        self.ignored_namespaces
            .best_candidates_match(candidates)
            .is_some()
    }
}

#[derive(Debug, Default)]
pub struct EffectConfigBuilder {
    config: EffectConfig,
}

impl EffectConfigBuilder {
    #[must_use]
    pub fn ignored_namespaces(mut self, paths: PathPatterns) -> Self {
        self.config.ignored_namespaces = paths;
        self
    }

    #[must_use]
    #[allow(dead_code)]
    pub fn trusted_boundary_namespaces(mut self, paths: PathPatterns) -> Self {
        self.config.trusted_boundary_namespaces = paths;
        self
    }

    #[must_use]
    pub fn operation(mut self, name: impl Into<String>, level: LintLevel) -> Self {
        let name = name.into();
        assert!(
            self.config
                .lints
                .operations
                .insert(name.clone(), level)
                .is_none(),
            "duplicate effect operation `{name}`"
        );
        self
    }

    #[must_use]
    pub fn operations(
        mut self,
        level: LintLevel,
        names: impl IntoIterator<Item = &'static str>,
    ) -> Self {
        for name in names {
            self = self.operation(name, level);
        }
        self
    }

    #[must_use]
    pub fn build(self) -> EffectConfig {
        self.config
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct EffectLintConfig {
    pub ambiguous_marker: LintLevel,
    pub ambiguous_requirement: LintLevel,
    pub invocation: LintLevel,
    pub operation: LintLevel,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub operations: BTreeMap<String, LintLevel>,
}

impl Default for EffectLintConfig {
    fn default() -> Self {
        Self {
            ambiguous_marker: LintLevel::Deny,
            ambiguous_requirement: LintLevel::Deny,
            invocation: LintLevel::Warn,
            operation: LintLevel::Warn,
            operations: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LintLevel {
    Allow,
    Warn,
    Deny,
}

impl LintLevel {
    #[must_use]
    pub fn is_allow(self) -> bool {
        self == Self::Allow
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct CoverageConfig {
    pub unresolved_call_target: LintLevel,
    pub analysis_incomplete: LintLevel,
}

impl Default for CoverageConfig {
    fn default() -> Self {
        Self {
            unresolved_call_target: LintLevel::Warn,
            analysis_incomplete: LintLevel::Deny,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EffectiveCoverageConfig {
    pub(crate) unresolved_call_target: LintLevel,
    pub(crate) analysis_incomplete: LintLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EffectFindingLints {
    pub(crate) concrete_invocation: LintLevel,
    pub(crate) ambiguous_marker: LintLevel,
    pub(crate) ambiguous_requirement: LintLevel,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RawEffectConfig {
    ignored_namespaces: Option<PathPatterns>,
    trusted_boundary_namespaces: Option<PathPatterns>,
    lints: Option<RawEffectLints>,
    coverage: Option<RawCoverage>,
    #[serde(flatten)]
    unknown: BTreeMap<String, toml::Value>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RawEffectLints {
    ambiguous_marker: Option<LintLevel>,
    ambiguous_requirement: Option<LintLevel>,
    invocation: Option<LintLevel>,
    operation: Option<LintLevel>,
    #[serde(default)]
    operations: BTreeMap<String, LintLevel>,
    #[serde(flatten)]
    unknown: BTreeMap<String, toml::Value>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RawCoverage {
    unresolved_call_target: Option<LintLevel>,
    analysis_incomplete: Option<LintLevel>,
    #[serde(flatten)]
    unknown: BTreeMap<String, toml::Value>,
}

fn warn_unknown_fields(
    prefix: &str,
    fields: BTreeMap<String, toml::Value>,
    warnings: &mut Vec<ConfigWarning>,
) {
    for name in fields.keys() {
        warnings.push(ConfigWarning {
            field: format!("{prefix}.{name}"),
            message: String::from("unknown configuration field; ignored"),
        });
    }
}

impl RawEffectConfig {
    fn apply(self, effect: &str, config: &mut EffectConfig, warnings: &mut Vec<ConfigWarning>) {
        if let Some(paths) = self.ignored_namespaces {
            config.ignored_namespaces = paths;
        }
        if let Some(paths) = self.trusted_boundary_namespaces {
            config.trusted_boundary_namespaces = paths;
        }
        warn_unknown_fields(effect, self.unknown, warnings);
        if let Some(lints) = self.lints {
            let prefix = format!("{effect}.lints");
            if let Some(level) = lints.ambiguous_marker {
                config.lints.ambiguous_marker = level;
            }
            if let Some(level) = lints.ambiguous_requirement {
                config.lints.ambiguous_requirement = level;
            }
            if let Some(level) = lints.invocation {
                config.lints.invocation = level;
            }
            if let Some(level) = lints.operation {
                config.lints.operation = level;
                for operation_level in config.lints.operations.values_mut() {
                    *operation_level = level;
                }
            }
            warn_unknown_fields(&prefix, lints.unknown, warnings);
            for (name, level) in lints.operations {
                if let Some(default) = config.lints.operations.get_mut(&name) {
                    *default = level;
                } else {
                    warnings.push(ConfigWarning {
                        field: format!("{prefix}.operations.{name}"),
                        message: String::from("unsupported effect operation; ignored"),
                    });
                }
            }
        }
        if let Some(coverage) = self.coverage {
            if let Some(level) = coverage.unresolved_call_target {
                config.coverage.unresolved_call_target = level;
            }
            if let Some(level) = coverage.analysis_incomplete {
                config.coverage.analysis_incomplete = level;
            }
            warn_unknown_fields(&format!("{effect}.coverage"), coverage.unknown, warnings);
        }
    }
}

/// Current-crate functions whose reachable effect paths should be reported.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ReportRootSet {
    /// Report from public exported functions.
    #[default]
    Public,
    /// Report from every analyzable local function item.
    All,
    /// Report from these fully qualified current-crate function paths.
    Explicit(Vec<ReportRootPath>),
}

impl ReportRootSet {
    #[must_use]
    pub fn description(&self) -> String {
        match self {
            Self::Public => String::from("\"public\""),
            Self::All => String::from("\"all\""),
            Self::Explicit(roots) => match roots.len() {
                1 => String::from("1 explicit path"),
                count => format!("{count} explicit paths"),
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReportRootPath {
    path: String,
    source_span: Range<usize>,
}

impl ReportRootPath {
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub fn source_span(&self) -> Range<usize> {
        self.source_span.clone()
    }
}

impl PartialEq for ReportRootPath {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
    }
}

impl Eq for ReportRootPath {}

impl<'de> Deserialize<'de> for ReportRootPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let spanned = Spanned::<String>::deserialize(deserializer)?;
        let source_span = spanned.span();
        Ok(Self {
            path: spanned.into_inner(),
            source_span,
        })
    }
}

impl<'de> Deserialize<'de> for ReportRootSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ReportRootSetVisitor;

        impl<'de> serde::de::Visitor<'de> for ReportRootSetVisitor {
            type Value = ReportRootSet;

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match value {
                    "public" => Ok(ReportRootSet::Public),
                    "all" => Ok(ReportRootSet::All),
                    other => Err(E::custom(format!(
                        "invalid report roots: {other}, expected 'public', 'all', or an array of strings"
                    ))),
                }
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut paths = Vec::new();
                while let Some(path) = seq.next_element::<ReportRootPath>()? {
                    paths.push(path);
                }
                Ok(ReportRootSet::Explicit(paths))
            }

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(
                    formatter,
                    "a string 'public' or 'all', or an array of current-crate function paths"
                )
            }
        }

        deserializer.deserialize_any(ReportRootSetVisitor)
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
    OverrideIo {
        path: PathBuf,
        source: std::io::Error,
    },
    OverrideParse {
        path: PathBuf,
        source: toml::de::Error,
    },
    OverrideGlob {
        path: PathBuf,
        source: globset::Error,
    },
}

impl Display for ConfigError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, .. } => {
                write!(f, "failed to read {}", path.display())
            }
            Self::Parse { path, .. } => {
                write!(f, "failed to parse {}", path.display())
            }
            Self::OverrideIo { path, .. } => {
                write!(
                    f,
                    "failed to read contract override file {}",
                    path.display()
                )
            }
            Self::OverrideParse { path, .. } => {
                write!(
                    f,
                    "failed to parse contract override file {}",
                    path.display()
                )
            }
            Self::OverrideGlob { path, .. } => {
                write!(
                    f,
                    "failed to compile contract override globs in {}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } | Self::OverrideIo { source, .. } => Some(source),
            Self::Parse { source, .. } | Self::OverrideParse { source, .. } => Some(source),
            Self::OverrideGlob { source, .. } => Some(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        AnalysisConfig, CompilerConfig, ConfigError, ContractDocOverrideFile, ContractDocOverrides,
        CoverageConfig, EXAMPLE_MANIFEST, EffectConfig, EffectDocMatching, LintLevel,
        MarkerProbing, MirInlining, OverflowChecks, PathPatterns, ReportRootSet, SniffTestConfig,
    };

    fn path_patterns(patterns: &[&str]) -> PathPatterns {
        PathPatterns::new(
            patterns
                .iter()
                .map(|pattern| (*pattern).to_owned())
                .collect(),
        )
        .expect("patterns should compile")
    }

    fn candidates(paths: &[&str]) -> Vec<String> {
        paths.iter().map(|path| (*path).to_owned()).collect()
    }

    fn trusts_boundary(config: &EffectConfig, candidates: &[String]) -> bool {
        config
            .trusted_boundary_namespaces()
            .best_candidates_match(candidates)
            .is_some()
    }

    #[test]
    fn config_errors_preserve_context_and_their_source() {
        let path = PathBuf::from("sniff-test.toml");
        let manifest_parse = toml::from_str::<SniffTestConfig>("invalid = [")
            .expect_err("manifest should be invalid");
        let manifest_parse_message = manifest_parse.to_string();
        let override_parse = toml::from_str::<ContractDocOverrideFile>("overrides = [")
            .expect_err("override should be invalid");
        let override_parse_message = override_parse.to_string();
        let override_glob = globset::Glob::new("[").expect_err("glob should be invalid");
        let override_glob_message = override_glob.to_string();
        let errors = [
            (
                ConfigError::Io {
                    path: path.clone(),
                    source: std::io::Error::new(std::io::ErrorKind::NotFound, "read source"),
                },
                "failed to read sniff-test.toml",
                String::from("read source"),
            ),
            (
                ConfigError::Parse {
                    path: path.clone(),
                    source: manifest_parse,
                },
                "failed to parse sniff-test.toml",
                manifest_parse_message,
            ),
            (
                ConfigError::OverrideIo {
                    path: path.clone(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "override read source",
                    ),
                },
                "failed to read contract override file sniff-test.toml",
                String::from("override read source"),
            ),
            (
                ConfigError::OverrideParse {
                    path: path.clone(),
                    source: override_parse,
                },
                "failed to parse contract override file sniff-test.toml",
                override_parse_message,
            ),
            (
                ConfigError::OverrideGlob {
                    path,
                    source: override_glob,
                },
                "failed to compile contract override globs in sniff-test.toml",
                override_glob_message,
            ),
        ];

        for (error, context, source) in errors {
            assert_eq!(error.to_string(), context);
            assert_eq!(
                std::error::Error::source(&error)
                    .expect("config error should retain its source")
                    .to_string(),
                source
            );
        }
    }

    #[test]
    fn manifest_warns_on_unknown_effect_fields_and_rejects_other_unknown_fields() {
        for (manifest, field) in [
            ("[analysis]\nnode-limt = 10", "node-limt"),
            ("[documentation]\noverride-files = []", "documentation"),
            (
                "[analysis]\ncallable-edge-attribution = \"call-sites\"",
                "callable-edge-attribution",
            ),
            (
                "[panic]\ntrusted-panic-boundary-namespaces = []",
                "trusted-panic-boundary-namespaces",
            ),
            (
                "[safety]\ntrusted-safety-boundary-namespaces = []",
                "trusted-safety-boundary-namespaces",
            ),
            ("[panic.lints]\ntrusted-panic = \"allow\"", "trusted-panic"),
            (
                "[safety.lints]\ntrusted-safety = \"allow\"",
                "trusted-safety",
            ),
            (
                "[safety.lints]\nsafety-obligation-missing-requirements = \"deny\"",
                "safety-obligation-missing-requirements",
            ),
            (
                "[panic.lints]\ndocumented-panic = \"warn\"",
                "documented-panic",
            ),
            (
                "[safety.lints]\nsafety-obligation-missing-justification = \"warn\"",
                "safety-obligation-missing-justification",
            ),
            (
                "[analysis.lints]\nempty-report-roots = \"allow\"",
                "empty-report-roots",
            ),
            (
                "[analysis.lints]\nmissing-report-root = \"deny\"",
                "missing-report-root",
            ),
            (
                "[panic.lints]\nindirect-call-boundary = \"warn\"",
                "indirect-call-boundary",
            ),
            (
                "[panic]\nunsafe-precondition-boundary-macros = []",
                "unsafe-precondition-boundary-macros",
            ),
        ] {
            if manifest.starts_with("[panic") || manifest.starts_with("[safety") {
                let config = SniffTestConfig::from_manifest_str(manifest)
                    .expect("unknown effect fields produce warnings");
                assert!(config.warnings[0].field.contains(field));
            } else {
                let error = SniffTestConfig::from_manifest_str(manifest)
                    .expect_err("unknown global fields should be rejected");
                let message = error.to_string();
                assert!(
                    (message.contains("unknown field")
                        || message.contains("unknown effect section"))
                        && message.contains(field),
                    "unexpected error for `{field}`: {message}"
                );
            }
        }
    }

    #[test]
    fn parses_contracts_and_domain_local_trusted_boundary_namespaces() {
        let config = r#"
            [contracts]
            override-files = []

            [panic]
            trusted-boundary-namespaces = ["core::**"]

            [safety]
            trusted-boundary-namespaces = ["ffi::safe_contract"]
        "#;

        let parsed = SniffTestConfig::from_manifest_str(config).expect("manifest should parse");

        assert!(trusts_boundary(
            &parsed.effect("panic"),
            &candidates(&["core::fmt::write"])
        ));
        assert!(trusts_boundary(
            &parsed.effect("safety"),
            &candidates(&["ffi::safe_contract"])
        ));
    }

    #[test]
    fn parses_compiler_configuration_separately_from_analysis_policy() {
        let config = r#"
            [compiler]
            overflow-checks = "on"
            inline-mir = "profile"

            [analysis]
            show-full-stack-trace = true
            report-roots = "all"
            marker-probing = "source-callsite"
            effect-doc-matching = "exact"
        "#;

        let parsed = SniffTestConfig::from_manifest_str(config).expect("manifest should parse");

        assert!(parsed.analysis.show_full_stack_trace);
        assert_eq!(parsed.analysis.report_roots.get_ref(), &ReportRootSet::All);
        assert_eq!(parsed.compiler.overflow_checks, OverflowChecks::On);
        assert_eq!(parsed.compiler.inline_mir, MirInlining::Profile);
        assert_eq!(
            parsed.analysis.marker_probing,
            MarkerProbing::SourceCallsite
        );
        assert_eq!(
            parsed.analysis.effect_doc_matching,
            EffectDocMatching::Exact
        );
    }

    #[test]
    fn overflow_checks_and_overflow_lint_parse_independently() {
        for (overflow, expected_overflow) in [
            ("profile", OverflowChecks::Profile),
            ("on", OverflowChecks::On),
            ("off", OverflowChecks::Off),
        ] {
            let config = format!(
                "[compiler]\noverflow-checks = \"{overflow}\"\n\
                 [panic.lints.operations]\noverflow = \"deny\"\n"
            );
            let parsed = SniffTestConfig::from_manifest_str(&config)
                .expect("compiler behavior and lint policy should be independent");

            assert_eq!(parsed.compiler.overflow_checks, expected_overflow);
            assert_eq!(
                parsed.effect("panic").lints.operations.get("overflow"),
                Some(&LintLevel::Deny)
            );
        }
    }

    #[test]
    fn parses_effect_specific_lints_and_coverage() {
        let config = r#"
            [panic.lints]
            ambiguous-marker = "allow"
            ambiguous-requirement = "warn"

            [panic.coverage]
            analysis-incomplete = "warn"

            [safety.lints]
            ambiguous-marker = "warn"
            ambiguous-requirement = "allow"

            [safety.coverage]
            analysis-incomplete = "allow"
        "#;
        let parsed = SniffTestConfig::from_manifest_str(config).expect("manifest should parse");
        assert_eq!(
            parsed.effect("panic").lints.ambiguous_marker,
            LintLevel::Allow
        );
        assert_eq!(
            parsed.effect("panic").lints.ambiguous_requirement,
            LintLevel::Warn
        );
        assert_eq!(
            parsed
                .effect("panic")
                .effective_coverage()
                .analysis_incomplete,
            LintLevel::Warn
        );
        assert_eq!(
            parsed.effect("safety").lints.ambiguous_marker,
            LintLevel::Warn
        );
        assert_eq!(
            parsed.effect("safety").lints.ambiguous_requirement,
            LintLevel::Allow
        );
        assert_eq!(
            parsed
                .effect("safety")
                .effective_coverage()
                .analysis_incomplete,
            LintLevel::Allow
        );
    }

    #[test]
    fn analysis_lints_reject_effect_specific_keys() {
        for key in [
            "ambiguous-panic-marker",
            "ambiguous-safety-marker",
            "ambiguous-panic-requirement",
            "ambiguous-safety-requirement",
            "panic-analysis-incomplete",
            "safety-analysis-incomplete",
            "ambiguous-effect-marker",
            "ambiguous-effect-requirement",
            "analysis-incomplete",
        ] {
            let source = format!("[analysis.lints]\n{key} = \"warn\"\n");
            let error = SniffTestConfig::from_manifest_str(&source)
                .expect_err("old location must be rejected");
            assert!(error.to_string().contains(key), "{error}");
        }
    }

    #[test]
    fn partial_lint_tables_use_direct_field_defaults() {
        let config = r#"
            [analysis.lints]
            undocumented-effect-invocation = "deny"

            [panic.lints]
            invocation = "allow"

        "#;

        let parsed = SniffTestConfig::from_manifest_str(config).expect("manifest should parse");

        assert_eq!(
            parsed.analysis.lints.undocumented_effect_invocation,
            LintLevel::Deny
        );
        assert_eq!(
            parsed.effect("panic").lints.ambiguous_marker,
            LintLevel::Deny
        );
        assert_eq!(
            parsed.effect("safety").lints.ambiguous_marker,
            LintLevel::Deny
        );
        assert_eq!(parsed.effect("panic").lints.invocation, LintLevel::Allow);
        assert_eq!(parsed.effect("panic").lints.operation, LintLevel::Warn);
        assert_eq!(parsed.effect("safety").lints.invocation, LintLevel::Warn);
    }

    #[test]
    fn compiler_and_analysis_defaults_are_independent() {
        assert_eq!(
            CompilerConfig::default().overflow_checks,
            OverflowChecks::Profile
        );
        assert_eq!(CompilerConfig::default().inline_mir, MirInlining::Off);
        assert_eq!(
            AnalysisConfig::default().marker_probing,
            MarkerProbing::MacroDefinitionFirst
        );
        assert_eq!(
            AnalysisConfig::default().effect_doc_matching,
            EffectDocMatching::AnyJustification
        );
        assert_eq!(
            SniffTestConfig::default()
                .effect("panic")
                .lints
                .ambiguous_marker,
            LintLevel::Deny
        );
        assert_eq!(
            SniffTestConfig::default()
                .effect("safety")
                .lints
                .ambiguous_marker,
            LintLevel::Deny
        );
        assert_eq!(
            SniffTestConfig::default()
                .effect("panic")
                .lints
                .ambiguous_requirement,
            LintLevel::Deny
        );
        assert_eq!(
            SniffTestConfig::default()
                .effect("safety")
                .lints
                .ambiguous_requirement,
            LintLevel::Deny
        );
        assert_eq!(
            SniffTestConfig::default()
                .effect("panic")
                .effective_coverage()
                .analysis_incomplete,
            LintLevel::Deny
        );
        assert_eq!(
            SniffTestConfig::default()
                .effect("safety")
                .effective_coverage()
                .analysis_incomplete,
            LintLevel::Deny
        );
    }

    #[test]
    fn default_panic_lints_warn_on_unjustified_invocations_and_operations() {
        let lints = SniffTestConfig::default().effect("panic").lints.clone();

        assert_eq!(lints.operation, LintLevel::Warn);
        assert_eq!(lints.operations.len(), 11);
        assert_eq!(lints.invocation, LintLevel::Warn);
        assert_eq!(
            SniffTestConfig::default().effect("panic").coverage,
            CoverageConfig::default()
        );
        assert_eq!(
            SniffTestConfig::default()
                .effect("panic")
                .effective_coverage()
                .unresolved_call_target,
            LintLevel::Warn
        );
    }

    #[test]
    fn unsafe_precondition_macro_is_a_user_overridable_default_ignore() {
        let defaults = SniffTestConfig::default().effect("panic").clone();
        assert!(
            defaults
                .ignored_namespaces
                .best_match("core::ub_checks::assert_unsafe_precondition")
                .is_some()
        );

        let disabled = SniffTestConfig::from_manifest_str("[panic]\nignored-namespaces = []\n")
            .expect("an empty ignore list should be accepted");
        assert!(
            disabled
                .effect("panic")
                .ignored_namespaces
                .best_match("core::ub_checks::assert_unsafe_precondition")
                .is_none()
        );
        assert!(
            defaults
                .ignored_namespaces
                .best_match("sample::assert_unsafe_precondition")
                .is_none()
        );

        let replacement = SniffTestConfig::from_manifest_str(
            "[panic]\nignored-namespaces = [\"sample::generated::**\"]\n",
        )
        .expect("a custom ignore list should replace the default");
        assert!(
            replacement
                .effect("panic")
                .ignored_namespaces
                .best_match("sample::generated::assert_invariant")
                .is_some()
        );
        assert!(
            replacement
                .effect("panic")
                .ignored_namespaces
                .best_match("core::ub_checks::assert_unsafe_precondition")
                .is_none()
        );
    }

    #[test]
    fn example_manifest_trusts_standard_library_crates_while_empty_config_does_not() {
        let initialized = SniffTestConfig::from_manifest_str(EXAMPLE_MANIFEST)
            .expect("the example manifest should parse");
        for candidates in [
            candidates(&["core", "core::slice::raw::from_raw_parts"]),
            candidates(&["alloc", "alloc::vec::Vec::<T>::new"]),
            candidates(&["std", "std::collections::hash::map::HashMap::<K, V>::new"]),
        ] {
            assert!(trusts_boundary(&initialized.effect("panic"), &candidates));
            assert!(trusts_boundary(&initialized.effect("safety"), &candidates));
        }

        let empty = SniffTestConfig::default();
        let std_candidates = candidates(&["std", "std::collections::HashMap::new"]);
        assert!(!trusts_boundary(&empty.effect("panic"), &std_candidates));
        assert!(!trusts_boundary(&empty.effect("safety"), &std_candidates));
    }

    #[test]
    fn default_safety_lints_keep_findings_visible_without_failing() {
        let lints = SniffTestConfig::default().effect("safety").lints.clone();

        assert_eq!(
            SniffTestConfig::default()
                .effect("safety")
                .effective_coverage()
                .unresolved_call_target,
            LintLevel::Warn
        );
        assert_eq!(lints.invocation, LintLevel::Warn);
        assert_eq!(lints.operation, LintLevel::Warn);
        assert_eq!(lints.operations.len(), 11);
    }

    #[test]
    fn removed_safety_missing_requirements_lint_warns() {
        let config = SniffTestConfig::from_manifest_str(
            "[safety.lints]\nunsafe-call-missing-requirements = \"warn\"",
        )
        .expect("unknown fields produce warnings");
        assert!(
            config.warnings[0]
                .field
                .contains("unsafe-call-missing-requirements")
        );
    }

    #[test]
    fn effect_specific_base_lint_keys_warn() {
        for (effect, key) in [
            ("panic", "panic-invocation"),
            ("panic", "compiler-assert"),
            ("safety", "unsafe-call-missing-justification"),
            ("safety", "unsafe-op-missing-justification"),
        ] {
            let manifest = format!("[{effect}.lints]\n{key} = \"warn\"");
            let config = SniffTestConfig::from_manifest_str(&manifest)
                .expect("unknown fields produce warnings");
            assert!(config.warnings[0].field.contains(key));
        }
    }

    #[test]
    fn operation_lint_tables_warn_on_unknown_and_flat_keys() {
        for source in [
            "[panic.lints.operations]\nunknown-assert = \"warn\"",
            "[safety.lints.operations]\nunknown-unsafe-op = \"warn\"",
            "[panic.lints]\ncompiler-assert-overflow = \"warn\"",
            "[safety.lints]\ninline-assembly-missing-justification = \"warn\"",
        ] {
            let config = SniffTestConfig::from_manifest_str(source)
                .expect("unknown fields produce warnings");
            assert_eq!(config.warnings.len(), 1, "{source}");
        }
    }

    #[test]
    fn operation_overrides_merge_with_writer_defaults_and_warn_on_typos() {
        let config = SniffTestConfig::from_manifest_str(
            r#"
            [safety.lints]
            operation = "deny"
            [safety.lints.operations]
            raw-pointer-dereference = "allow"
            raw-pointer-derefernece = "allow"
            "#,
        )
        .expect("valid fields should still load");

        assert_eq!(
            config
                .effect("safety")
                .operation_lint(Some("raw-pointer-dereference")),
            LintLevel::Allow
        );
        assert_eq!(
            config
                .effect("safety")
                .operation_lint(Some("inline-assembly")),
            LintLevel::Deny
        );
        assert_eq!(config.warnings.len(), 1);
        assert_eq!(
            config.warnings[0].field,
            "safety.lints.operations.raw-pointer-derefernece"
        );
        assert!(
            !config
                .effect("safety")
                .lints
                .operations
                .contains_key("raw-pointer-derefernece")
        );
    }

    #[test]
    fn effect_sections_are_keyed_by_registered_effect_name() {
        let config = SniffTestConfig::from_manifest_str(
            "[panic.lints.operations]\nbounds-check = \"deny\"\n[safety.lints.operations]\ninline-assembly = \"allow\"",
        )
        .expect("registered effect sections should parse");
        assert_eq!(config.effects.len(), 2);
        assert_eq!(
            config.effect("panic").operation_lint(Some("bounds-check")),
            LintLevel::Deny
        );
        assert_eq!(
            config
                .effect("safety")
                .operation_lint(Some("inline-assembly")),
            LintLevel::Allow
        );
        assert!(SniffTestConfig::from_manifest_str("[panics]").is_err());
        assert!(SniffTestConfig::from_manifest_str("[allocation]").is_err());
    }

    #[test]
    fn invalid_level_remains_a_parse_error() {
        assert!(
            SniffTestConfig::from_manifest_str(
                "[safety.lints.operations]\nraw-pointer-dereference = \"severe\""
            )
            .is_err()
        );
    }

    #[test]
    fn coverage_sections_set_levels_and_preserve_defaults() {
        let config = SniffTestConfig::from_manifest_str(
            r#"
            [panic.coverage]
            unresolved-call-target = "deny"
            analysis-incomplete = "deny"

            [safety.coverage]
            unresolved-call-target = "allow"
            "#,
        )
        .expect("coverage configuration");
        let panic = config.effect("panic").effective_coverage();
        assert_eq!(panic.unresolved_call_target, LintLevel::Deny);
        assert_eq!(panic.analysis_incomplete, LintLevel::Deny);
        let safety = config.effect("safety").effective_coverage();
        assert_eq!(safety.unresolved_call_target, LintLevel::Allow);
        assert_eq!(safety.analysis_incomplete, LintLevel::Deny);
    }

    #[test]
    fn parses_panic_lint_levels() {
        let config = r#"
            [panic.lints]
            operation = "warn"
            invocation = "allow"

            [panic.coverage]
            unresolved-call-target = "deny"

            [panic.lints.operations]
            bounds-check = "allow"
            overflow = "warn"
            overflow-negation = "deny"
            division-by-zero = "allow"
            remainder-by-zero = "warn"
            resumed-after-return = "deny"
            resumed-after-panic = "allow"
            resumed-after-drop = "warn"
            misaligned-pointer-dereference = "deny"
            null-pointer-dereference = "allow"
            invalid-enum-construction = "warn"
        "#;

        let parsed = SniffTestConfig::from_manifest_str(config).expect("manifest should parse");

        assert_eq!(parsed.effect("panic").lints.operation, LintLevel::Warn);
        let overrides = &parsed.effect("panic").lints.operations;
        assert_eq!(overrides.len(), 11);
        for (kind, level) in [
            ("bounds-check", LintLevel::Allow),
            ("overflow", LintLevel::Warn),
            ("overflow-negation", LintLevel::Deny),
            ("division-by-zero", LintLevel::Allow),
            ("remainder-by-zero", LintLevel::Warn),
            ("resumed-after-return", LintLevel::Deny),
            ("resumed-after-panic", LintLevel::Allow),
            ("resumed-after-drop", LintLevel::Warn),
            ("misaligned-pointer-dereference", LintLevel::Deny),
            ("null-pointer-dereference", LintLevel::Allow),
            ("invalid-enum-construction", LintLevel::Warn),
        ] {
            assert_eq!(overrides.get(kind), Some(&level));
        }
        assert_eq!(parsed.effect("panic").lints.invocation, LintLevel::Allow);
        assert_eq!(
            parsed.effect("panic").operation_lint(Some("bounds-check")),
            LintLevel::Allow
        );
        assert_eq!(parsed.effect("panic").operation_lint(None), LintLevel::Warn);
        assert_eq!(
            parsed.effect("panic").coverage.unresolved_call_target,
            LintLevel::Deny
        );
    }

    #[test]
    fn safety_configuration_preserves_namespace_and_lint_policy() {
        let config = r#"
            [safety]
            ignored-namespaces = ["bindgen::**", "my_crate::ffi"]
            trusted-boundary-namespaces = ["ffi::safe_contract", "ffi::safe_method"]

            [safety.lints]
            invocation = "deny"
            operation = "deny"

            [safety.coverage]
            unresolved-call-target = "deny"
        "#;

        let parsed = SniffTestConfig::from_manifest_str(config).expect("manifest should parse");

        assert!(parsed.effect("safety").ignores_candidates(&candidates(&[
            "my_crate::caller",
            "bindgen::root::unsafe_fn",
        ])));
        assert!(
            !parsed
                .effect("safety")
                .ignores_candidates(&candidates(&["my_crate::safe"]))
        );
        assert!(trusts_boundary(
            &parsed.effect("safety"),
            &candidates(&["ffi::safe_contract"])
        ));
        assert!(!trusts_boundary(
            &parsed.effect("safety"),
            &candidates(&["ffi::plain_safe"])
        ));
        assert_eq!(parsed.effect("safety").lints.invocation, LintLevel::Deny);
        assert_eq!(parsed.effect("safety").lints.operation, LintLevel::Deny);
        assert_eq!(
            parsed.effect("safety").coverage.unresolved_call_target,
            LintLevel::Deny
        );
    }

    #[test]
    fn parses_safety_operation_lint_overrides() {
        let config = r#"
            [safety.lints]
            operation = "deny"

            [safety.lints.operations]
            raw-pointer-dereference = "allow"
            mutable-static-access = "warn"
            extern-static-access = "deny"
            union-field-access = "allow"
            unsafe-field-access = "warn"
            layout-constrained-type-initialization = "deny"
            unsafe-field-initialization = "allow"
            layout-constrained-field-mutation = "warn"
            layout-constrained-field-borrow = "deny"
            inline-assembly = "allow"
            unsafe-binder-cast = "warn"
        "#;

        let parsed = SniffTestConfig::from_manifest_str(config).expect("manifest should parse");
        let overrides = &parsed.effect("safety").lints.operations;
        assert_eq!(overrides.len(), 11);
        for (kind, level) in [
            ("raw-pointer-dereference", LintLevel::Allow),
            ("mutable-static-access", LintLevel::Warn),
            ("extern-static-access", LintLevel::Deny),
            ("union-field-access", LintLevel::Allow),
            ("unsafe-field-access", LintLevel::Warn),
            ("layout-constrained-type-initialization", LintLevel::Deny),
            ("unsafe-field-initialization", LintLevel::Allow),
            ("layout-constrained-field-mutation", LintLevel::Warn),
            ("layout-constrained-field-borrow", LintLevel::Deny),
            ("inline-assembly", LintLevel::Allow),
            ("unsafe-binder-cast", LintLevel::Warn),
        ] {
            assert_eq!(overrides.get(kind), Some(&level));
        }
        assert_eq!(
            parsed
                .effect("safety")
                .operation_lint(Some("raw-pointer-dereference")),
            LintLevel::Allow
        );
        assert_eq!(
            parsed.effect("safety").operation_lint(None),
            LintLevel::Deny
        );
    }

    #[test]
    fn operation_defaults_serialize_with_overrides() {
        let mut panic_lints = SniffTestConfig::default().effect("panic").lints.clone();
        panic_lints
            .operations
            .insert(String::from("bounds-check"), LintLevel::Warn);
        let serialized = toml::to_string(&panic_lints).expect("panic lint config should serialize");
        assert!(serialized.contains("[operations]\nbounds-check = \"warn\""));
        assert!(serialized.contains("overflow = \"warn\""));

        let mut safety_lints = SniffTestConfig::default().effect("safety").lints.clone();
        safety_lints
            .operations
            .insert(String::from("inline-assembly"), LintLevel::Deny);
        let serialized =
            toml::to_string(&safety_lints).expect("safety lint config should serialize");
        assert!(serialized.contains("inline-assembly = \"deny\""));
        assert!(serialized.contains("raw-pointer-dereference = \"warn\""));

        assert!(
            toml::to_string(&SniffTestConfig::default().effect("panic").lints)
                .expect("default panic lints serialize")
                .contains("[operations]")
        );
    }

    #[test]
    fn mir_inlining_off_disables_mir_inline_passes() {
        assert_eq!(
            MirInlining::Off.rustc_flags(),
            [
                "inline-mir=no",
                "inline-mir-threshold=0",
                "inline-mir-forwarder-threshold=0",
                "inline-mir-hint-threshold=0",
                "mir-enable-passes=-Inline,-ForceInline",
            ]
        );
    }

    #[test]
    fn panic_namespace_policies_use_stable_candidate_sets() {
        let config = EffectConfig {
            ignored_namespaces: path_patterns(&["generated::**"]),
            trusted_boundary_namespaces: path_patterns(&["core::**", "compat::panic"]),
            ..SniffTestConfig::default().effect("panic").clone()
        };

        assert!(config.ignores_candidates(&candidates(&["app::wrapper", "generated::helper",])));
        assert!(trusts_boundary(&config, &candidates(&["core::fmt::write"])));
        assert!(trusts_boundary(
            &config,
            &candidates(&["core::panicking::panic_fmt"])
        ));
        assert!(trusts_boundary(
            &config,
            &candidates(&["compat::panic", "canonical::panic"])
        ));
        assert!(!trusts_boundary(&config, &candidates(&["app::run"])));
    }

    #[test]
    fn example_manifest_preserves_ignored_macro_paths() {
        let config = SniffTestConfig::from_manifest_str(EXAMPLE_MANIFEST)
            .expect("example manifest should parse");

        assert!(
            config
                .effect("panic")
                .ignored_namespaces
                .best_match("core::ub_checks::assert_unsafe_precondition")
                .is_some()
        );
    }

    #[test]
    fn manifest_validates_namespace_globs() {
        let config = r#"
            [panic]
            ignored-namespaces = ["std::ops::{Index"]
        "#;

        let error = SniffTestConfig::from_manifest_str(config)
            .expect_err("invalid glob patterns should be rejected");

        assert!(error.to_string().contains("error parsing glob"));
    }

    #[test]
    fn manifest_warns_on_removed_panic_sink_namespaces() {
        let config = SniffTestConfig::from_manifest_str(
            "[panic]\npanic-sink-namespaces = [\"core::panicking::**\"]",
        )
        .expect("removed fields produce warnings");

        assert!(config.warnings[0].field.contains("panic-sink-namespaces"));
    }

    #[test]
    fn parses_report_roots() {
        let all = r#"
            [analysis]
            report-roots = "all"
        "#;
        let explicit = r#"
            [analysis]
            report-roots = ["test::a", "test::b"]
        "#;

        let parsed_all = SniffTestConfig::from_manifest_str(all).expect("manifest should parse");
        let parsed_explicit =
            SniffTestConfig::from_manifest_str(explicit).expect("manifest should parse");
        assert_eq!(
            parsed_all.analysis.report_roots.get_ref(),
            &ReportRootSet::All
        );
        let ReportRootSet::Explicit(paths) = parsed_explicit.analysis.report_roots.get_ref() else {
            panic!("explicit report roots should parse as explicit paths");
        };
        assert_eq!(paths[0].path(), "test::a");
        assert_eq!(paths[1].path(), "test::b");
        assert_eq!(&explicit[paths[0].source_span()], "\"test::a\"");
        assert_eq!(&explicit[paths[1].source_span()], "\"test::b\"");
    }

    #[test]
    fn report_roots_retain_the_entire_config_value_span() {
        for (manifest, expected) in [
            ("[analysis]\nreport-roots = \"all\"\n", "\"all\""),
            ("[analysis]\nreport-roots = []\n", "[]"),
            (
                "[analysis]\nreport-roots = [\"test::a\", \"test::b\"]\n",
                "[\"test::a\", \"test::b\"]",
            ),
        ] {
            let parsed =
                SniffTestConfig::from_manifest_str(manifest).expect("manifest should parse");
            let span = parsed.analysis.report_roots.span();

            assert_eq!(&manifest[span], expected);
        }
    }

    #[test]
    fn parses_contract_override_files() {
        let config = r#"
            [contracts]
            override-files = ["override.toml", "audit/zerocopy.toml"]
        "#;

        let parsed = SniffTestConfig::from_manifest_str(config).expect("manifest should parse");

        assert_eq!(
            parsed.contracts.override_files,
            [
                PathBuf::from("override.toml"),
                PathBuf::from("audit/zerocopy.toml")
            ]
        );
    }

    #[test]
    fn contract_overrides_use_most_specific_namespace_glob() {
        let overrides = ContractDocOverrides::new(vec![
            ("zerocopy::**".to_owned(), "# Safety\n".to_owned()),
            (
                "zerocopy::Layout::for_type".to_owned(),
                "# Panics\n".to_owned(),
            ),
        ])
        .expect("override globs should compile");

        assert_eq!(
            overrides.markdown_for_candidates(&candidates(&[
                "zerocopy::impls::{impl#0}::for_type",
                "zerocopy::Layout::for_type",
            ])),
            Some("# Panics\n")
        );
        assert_eq!(
            overrides.markdown_for_candidates(&candidates(&["zerocopy::FromBytes"])),
            Some("# Safety\n")
        );
    }

    #[test]
    fn manifest_loads_contract_overrides_relative_to_itself() {
        let dir = tempfile::tempdir().expect("tempdir should be created");
        let manifest_path = dir.path().join("sniff-test.toml");
        let override_path = dir.path().join("override.toml");
        std::fs::write(
            &manifest_path,
            r#"
                [contracts]
                override-files = ["override.toml"]
            "#,
        )
        .expect("manifest should be written");
        std::fs::write(
            &override_path,
            r#"
                [overrides]
                "zerocopy::Layout::for_type" = """
                # Panics

                - nonzero: layout size must be representable.
                """
            "#,
        )
        .expect("override file should be written");

        let parsed =
            SniffTestConfig::from_manifest_path(&manifest_path).expect("manifest should load");

        assert_eq!(
            parsed.contracts.resolved_override_files(),
            std::slice::from_ref(&override_path)
        );
        assert_eq!(
            parsed
                .contracts
                .overrides
                .markdown_for_candidates(&candidates(&["zerocopy::Layout::for_type"]))
                .map(str::trim),
            Some("# Panics\n\n- nonzero: layout size must be representable.")
        );
    }
}
