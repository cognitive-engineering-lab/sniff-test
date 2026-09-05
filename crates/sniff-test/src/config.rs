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

use serde::{Deserialize, Deserializer, Serialize};
use toml::Spanned;

use crate::contracts::ContractDocOverrides;
use crate::path_patterns::PathPatterns;

pub const DEFAULT_MANIFEST_FILE: &str = "sniff-test.toml";
pub const EXAMPLE_MANIFEST: &str = include_str!("../example-manifest.toml");

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SniffTestConfig {
    #[serde(default)]
    pub compiler: CompilerConfig,
    #[serde(default)]
    pub analysis: AnalysisConfig,
    #[serde(default)]
    pub contracts: ContractsConfig,
    #[serde(default)]
    pub panics: PanicConfig,
    #[serde(default)]
    pub safety: SafetyConfig,
}

impl SniffTestConfig {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct AnalysisLintConfig {
    pub ambiguous_panic_marker: LintLevel,
    pub ambiguous_safety_marker: LintLevel,
    pub ambiguous_panic_requirement: LintLevel,
    pub ambiguous_safety_requirement: LintLevel,
    pub panic_analysis_incomplete: LintLevel,
    pub safety_analysis_incomplete: LintLevel,
    pub empty_report_roots: LintLevel,
    pub missing_report_root: LintLevel,
}

impl Default for AnalysisLintConfig {
    fn default() -> Self {
        Self {
            ambiguous_panic_marker: LintLevel::Deny,
            ambiguous_safety_marker: LintLevel::Deny,
            ambiguous_panic_requirement: LintLevel::Deny,
            ambiguous_safety_requirement: LintLevel::Deny,
            // A truncated traversal proves nothing about the missing region.
            panic_analysis_incomplete: LintLevel::Deny,
            safety_analysis_incomplete: LintLevel::Deny,
            empty_report_roots: LintLevel::Warn,
            missing_report_root: LintLevel::Warn,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
struct RawAnalysisLintConfig {
    ambiguous_panic_marker: Option<LintLevel>,
    ambiguous_safety_marker: Option<LintLevel>,
    ambiguous_panic_requirement: Option<LintLevel>,
    ambiguous_safety_requirement: Option<LintLevel>,
    panic_analysis_incomplete: Option<LintLevel>,
    safety_analysis_incomplete: Option<LintLevel>,
    empty_report_roots: Option<LintLevel>,
    missing_report_root: Option<LintLevel>,
    // Group defaults used when exact effect-specific values are absent.
    ambiguous_effect_marker: Option<LintLevel>,
    ambiguous_effect_requirement: Option<LintLevel>,
    analysis_incomplete: Option<LintLevel>,
}

impl<'de> Deserialize<'de> for AnalysisLintConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawAnalysisLintConfig::deserialize(deserializer)?;
        let defaults = Self::default();
        Ok(Self {
            ambiguous_panic_marker: raw
                .ambiguous_panic_marker
                .or(raw.ambiguous_effect_marker)
                .unwrap_or(defaults.ambiguous_panic_marker),
            ambiguous_safety_marker: raw
                .ambiguous_safety_marker
                .or(raw.ambiguous_effect_marker)
                .unwrap_or(defaults.ambiguous_safety_marker),
            ambiguous_panic_requirement: raw
                .ambiguous_panic_requirement
                .or(raw.ambiguous_effect_requirement)
                .unwrap_or(defaults.ambiguous_panic_requirement),
            ambiguous_safety_requirement: raw
                .ambiguous_safety_requirement
                .or(raw.ambiguous_effect_requirement)
                .unwrap_or(defaults.ambiguous_safety_requirement),
            panic_analysis_incomplete: raw
                .panic_analysis_incomplete
                .or(raw.analysis_incomplete)
                .unwrap_or(defaults.panic_analysis_incomplete),
            safety_analysis_incomplete: raw
                .safety_analysis_incomplete
                .or(raw.analysis_incomplete)
                .unwrap_or(defaults.safety_analysis_incomplete),
            empty_report_roots: raw
                .empty_report_roots
                .unwrap_or(defaults.empty_report_roots),
            missing_report_root: raw
                .missing_report_root
                .unwrap_or(defaults.missing_report_root),
        })
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
#[serde(default)]
pub struct PanicConfig {
    /// User-facing severity for panic finding classes.
    pub lints: PanicLintConfig,
    /// Definition paths whose internals are suppressed, or macro definition
    /// paths whose matching expansion branch terminates locally.
    pub ignored_namespaces: PathPatterns,
    /// Namespaces whose caller-visible panic contracts are trusted as complete.
    ///
    /// Matching implementations and their internal panic contracts are opaque.
    /// A matching API's own `# Panics` contract remains visible to non-trusted
    /// callers; an undocumented API is trusted as non-panicking.
    pub trusted_boundary_namespaces: PathPatterns,
    /// Callee paths treated as direct panic sinks.
    pub panic_sink_namespaces: PathPatterns,
}

impl Default for PanicConfig {
    fn default() -> Self {
        Self {
            lints: PanicLintConfig::default(),
            ignored_namespaces: PathPatterns::new(vec![String::from(
                "core::ub_checks::assert_unsafe_precondition",
            )])
            .expect("the built-in panic ignore path is valid"),
            trusted_boundary_namespaces: PathPatterns::default(),
            panic_sink_namespaces: PathPatterns::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct PanicLintConfig {
    pub compiler_assert: LintLevel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compiler_assert_bounds_check: Option<LintLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compiler_assert_overflow: Option<LintLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compiler_assert_overflow_negation: Option<LintLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compiler_assert_division_by_zero: Option<LintLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compiler_assert_remainder_by_zero: Option<LintLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compiler_assert_resumed_after_return: Option<LintLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compiler_assert_resumed_after_panic: Option<LintLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compiler_assert_resumed_after_drop: Option<LintLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compiler_assert_misaligned_pointer_dereference: Option<LintLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compiler_assert_null_pointer_dereference: Option<LintLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compiler_assert_invalid_enum_construction: Option<LintLevel>,
    pub panic_invocation: LintLevel,
    pub documented_panic: LintLevel,
    pub unresolved_call_target: LintLevel,
}

impl Default for PanicLintConfig {
    fn default() -> Self {
        Self {
            compiler_assert: LintLevel::Deny,
            compiler_assert_bounds_check: None,
            compiler_assert_overflow: None,
            compiler_assert_overflow_negation: None,
            compiler_assert_division_by_zero: None,
            compiler_assert_remainder_by_zero: None,
            compiler_assert_resumed_after_return: None,
            compiler_assert_resumed_after_panic: None,
            compiler_assert_resumed_after_drop: None,
            compiler_assert_misaligned_pointer_dereference: None,
            compiler_assert_null_pointer_dereference: None,
            compiler_assert_invalid_enum_construction: None,
            panic_invocation: LintLevel::Deny,
            documented_panic: LintLevel::Warn,
            unresolved_call_target: LintLevel::Allow,
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

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
#[serde(default)]
pub struct SafetyConfig {
    /// Namespaces whose safety findings should be suppressed.
    pub ignored_namespaces: PathPatterns,
    /// Namespaces whose caller-visible safety contracts are trusted as complete.
    ///
    /// Matching implementations and their internal safety contracts are opaque.
    /// A matching API's own `# Safety` contract remains visible to non-trusted
    /// callers. A direct local unsafe invocation is not suppressed by the
    /// target's membership in this list.
    pub trusted_boundary_namespaces: PathPatterns,
    pub lints: SafetyLintConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct SafetyLintConfig {
    pub missing_safety_docs: LintLevel,
    pub unresolved_call_target: LintLevel,
    pub unsafe_call_missing_justification: LintLevel,
    pub unsafe_call_missing_requirements: LintLevel,
    pub unsafe_op_missing_justification: LintLevel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_pointer_dereference_missing_justification: Option<LintLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mutable_static_access_missing_justification: Option<LintLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extern_static_access_missing_justification: Option<LintLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub union_field_access_missing_justification: Option<LintLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsafe_field_access_missing_justification: Option<LintLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layout_constrained_type_initialization_missing_justification: Option<LintLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsafe_field_initialization_missing_justification: Option<LintLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layout_constrained_field_mutation_missing_justification: Option<LintLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layout_constrained_field_borrow_missing_justification: Option<LintLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inline_assembly_missing_justification: Option<LintLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsafe_binder_cast_missing_justification: Option<LintLevel>,
    pub safety_obligation_missing_justification: LintLevel,
    pub safety_obligation_missing_requirements: LintLevel,
}

impl Default for SafetyLintConfig {
    fn default() -> Self {
        Self {
            missing_safety_docs: LintLevel::Warn,
            unresolved_call_target: LintLevel::Allow,
            unsafe_call_missing_justification: LintLevel::Warn,
            unsafe_call_missing_requirements: LintLevel::Warn,
            unsafe_op_missing_justification: LintLevel::Warn,
            raw_pointer_dereference_missing_justification: None,
            mutable_static_access_missing_justification: None,
            extern_static_access_missing_justification: None,
            union_field_access_missing_justification: None,
            unsafe_field_access_missing_justification: None,
            layout_constrained_type_initialization_missing_justification: None,
            unsafe_field_initialization_missing_justification: None,
            layout_constrained_field_mutation_missing_justification: None,
            layout_constrained_field_borrow_missing_justification: None,
            inline_assembly_missing_justification: None,
            unsafe_binder_cast_missing_justification: None,
            safety_obligation_missing_justification: LintLevel::Warn,
            safety_obligation_missing_requirements: LintLevel::Warn,
        }
    }
}

impl PanicConfig {
    #[must_use]
    pub(crate) fn ignores_path(&self, path: &str) -> bool {
        self.ignored_namespaces.best_match(path).is_some()
    }

    #[must_use]
    pub(crate) fn ignores_candidates(&self, candidates: &[String]) -> bool {
        self.ignored_namespaces
            .best_candidates_match(candidates)
            .is_some()
    }

    #[must_use]
    pub(crate) fn panic_boundary_policy_candidates(
        &self,
        candidates: &[String],
    ) -> PanicBoundaryPolicy {
        let sink = self.panic_sink_namespaces.best_candidates_match(candidates);
        let trusted = self
            .trusted_boundary_namespaces
            .best_candidates_match(candidates);
        match (sink, trusted) {
            (Some(sink), Some(trusted)) if trusted.precision > sink.precision => {
                PanicBoundaryPolicy::TrustedBoundary
            }
            (Some(_), Some(_) | None) => PanicBoundaryPolicy::PanicSink,
            (None, Some(_)) => PanicBoundaryPolicy::TrustedBoundary,
            (None, None) => PanicBoundaryPolicy::Normal,
        }
    }
}

impl SafetyConfig {
    #[must_use]
    pub(crate) fn ignores_candidates(&self, candidates: &[String]) -> bool {
        self.ignored_namespaces
            .best_candidates_match(candidates)
            .is_some()
    }

    #[must_use]
    pub(crate) fn trusts_safety_boundary_candidates(&self, candidates: &[String]) -> bool {
        self.trusted_boundary_namespaces
            .best_candidates_match(candidates)
            .is_some()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanicBoundaryPolicy {
    PanicSink,
    TrustedBoundary,
    Normal,
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
        AnalysisConfig, AnalysisLintConfig, CompilerConfig, ConfigError, ContractDocOverrideFile,
        ContractDocOverrides, EXAMPLE_MANIFEST, EffectDocMatching, LintLevel, MarkerProbing,
        MirInlining, OverflowChecks, PanicBoundaryPolicy, PanicConfig, PathPatterns, ReportRootSet,
        SafetyConfig, SniffTestConfig,
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
    fn manifest_rejects_unknown_fields_including_removed_names() {
        for (manifest, field) in [
            ("[analysis]\nnode-limt = 10", "node-limt"),
            ("[documentation]\noverride-files = []", "documentation"),
            (
                "[analysis]\ncallable-edge-attribution = \"call-sites\"",
                "callable-edge-attribution",
            ),
            (
                "[panics]\ntrusted-panic-boundary-namespaces = []",
                "trusted-panic-boundary-namespaces",
            ),
            (
                "[safety]\ntrusted-safety-boundary-namespaces = []",
                "trusted-safety-boundary-namespaces",
            ),
            ("[panics.lints]\ntrusted-panic = \"allow\"", "trusted-panic"),
            (
                "[safety.lints]\ntrusted-safety = \"allow\"",
                "trusted-safety",
            ),
            (
                "[panics.lints]\nindirect-call-boundary = \"warn\"",
                "indirect-call-boundary",
            ),
            (
                "[panics]\nunsafe-precondition-boundary-macros = []",
                "unsafe-precondition-boundary-macros",
            ),
        ] {
            let error = SniffTestConfig::from_manifest_str(manifest)
                .expect_err("unknown config fields should be rejected");
            let message = error.to_string();

            assert!(
                message.contains("unknown field") && message.contains(field),
                "unexpected parse error for `{field}`: {message}"
            );
        }
    }

    #[test]
    fn parses_contracts_and_domain_local_trusted_boundary_namespaces() {
        let config = r#"
            [contracts]
            override-files = []

            [panics]
            trusted-boundary-namespaces = ["core::**"]

            [safety]
            trusted-boundary-namespaces = ["ffi::safe_contract"]
        "#;

        let parsed = SniffTestConfig::from_manifest_str(config).expect("manifest should parse");

        assert_eq!(
            parsed
                .panics
                .panic_boundary_policy_candidates(&candidates(&["core::fmt::write"])),
            PanicBoundaryPolicy::TrustedBoundary
        );
        assert!(
            parsed
                .safety
                .trusts_safety_boundary_candidates(&candidates(&["ffi::safe_contract"]))
        );
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
                 [panics.lints]\ncompiler-assert-overflow = \"deny\"\n"
            );
            let parsed = SniffTestConfig::from_manifest_str(&config)
                .expect("compiler behavior and lint policy should be independent");

            assert_eq!(parsed.compiler.overflow_checks, expected_overflow);
            assert_eq!(
                parsed.panics.lints.compiler_assert_overflow,
                Some(LintLevel::Deny)
            );
        }
    }

    #[test]
    fn parses_granular_analysis_lint_levels() {
        let config = r#"
            [analysis.lints]
            ambiguous-panic-marker = "allow"
            ambiguous-safety-marker = "warn"
            ambiguous-panic-requirement = "deny"
            ambiguous-safety-requirement = "allow"
            panic-analysis-incomplete = "warn"
            safety-analysis-incomplete = "deny"
            empty-report-roots = "deny"
            missing-report-root = "allow"
        "#;

        let parsed = SniffTestConfig::from_manifest_str(config).expect("manifest should parse");

        assert_eq!(
            parsed.analysis.lints.ambiguous_panic_marker,
            LintLevel::Allow
        );
        assert_eq!(
            parsed.analysis.lints.ambiguous_safety_marker,
            LintLevel::Warn
        );
        assert_eq!(
            parsed.analysis.lints.ambiguous_panic_requirement,
            LintLevel::Deny
        );
        assert_eq!(
            parsed.analysis.lints.ambiguous_safety_requirement,
            LintLevel::Allow
        );
        assert_eq!(
            parsed.analysis.lints.panic_analysis_incomplete,
            LintLevel::Warn
        );
        assert_eq!(
            parsed.analysis.lints.safety_analysis_incomplete,
            LintLevel::Deny
        );
        assert_eq!(parsed.analysis.lints.empty_report_roots, LintLevel::Deny);
        assert_eq!(parsed.analysis.lints.missing_report_root, LintLevel::Allow);
    }

    #[test]
    fn legacy_analysis_lint_umbrellas_seed_granular_levels() {
        let config = r#"
            [analysis.lints]
            ambiguous-effect-marker = "warn"
            ambiguous-effect-requirement = "allow"
            analysis-incomplete = "warn"
        "#;

        let parsed = SniffTestConfig::from_manifest_str(config).expect("manifest should parse");

        assert_eq!(
            parsed.analysis.lints.ambiguous_panic_marker,
            LintLevel::Warn
        );
        assert_eq!(
            parsed.analysis.lints.ambiguous_safety_marker,
            LintLevel::Warn
        );
        assert_eq!(
            parsed.analysis.lints.ambiguous_panic_requirement,
            LintLevel::Allow
        );
        assert_eq!(
            parsed.analysis.lints.ambiguous_safety_requirement,
            LintLevel::Allow
        );
        assert_eq!(
            parsed.analysis.lints.panic_analysis_incomplete,
            LintLevel::Warn
        );
        assert_eq!(
            parsed.analysis.lints.safety_analysis_incomplete,
            LintLevel::Warn
        );
    }

    #[test]
    fn granular_analysis_lints_override_legacy_umbrellas() {
        let config = r#"
            [analysis.lints]
            ambiguous-effect-marker = "allow"
            ambiguous-panic-marker = "deny"
            ambiguous-effect-requirement = "deny"
            ambiguous-safety-requirement = "warn"
            analysis-incomplete = "allow"
            safety-analysis-incomplete = "deny"
        "#;

        let parsed = SniffTestConfig::from_manifest_str(config).expect("manifest should parse");

        assert_eq!(
            parsed.analysis.lints.ambiguous_panic_marker,
            LintLevel::Deny
        );
        assert_eq!(
            parsed.analysis.lints.ambiguous_safety_marker,
            LintLevel::Allow
        );
        assert_eq!(
            parsed.analysis.lints.ambiguous_panic_requirement,
            LintLevel::Deny
        );
        assert_eq!(
            parsed.analysis.lints.ambiguous_safety_requirement,
            LintLevel::Warn
        );
        assert_eq!(
            parsed.analysis.lints.panic_analysis_incomplete,
            LintLevel::Allow
        );
        assert_eq!(
            parsed.analysis.lints.safety_analysis_incomplete,
            LintLevel::Deny
        );
    }

    #[test]
    fn serializes_only_canonical_analysis_lint_keys() {
        let serialized =
            toml::to_string(&AnalysisLintConfig::default()).expect("lint config should serialize");

        for key in [
            "ambiguous-panic-marker",
            "ambiguous-safety-marker",
            "ambiguous-panic-requirement",
            "ambiguous-safety-requirement",
            "panic-analysis-incomplete",
            "safety-analysis-incomplete",
        ] {
            assert!(serialized.contains(key), "missing canonical key `{key}`");
        }
        for legacy in [
            "ambiguous-effect-marker",
            "ambiguous-effect-requirement",
            "analysis-incomplete",
        ] {
            assert!(
                !serialized
                    .lines()
                    .any(|line| line.starts_with(&format!("{legacy} ="))),
                "serialized legacy key `{legacy}`"
            );
        }
    }

    #[test]
    fn partial_lint_tables_use_direct_field_defaults() {
        let config = r#"
            [analysis.lints]
            empty-report-roots = "deny"

            [panics.lints]
            panic-invocation = "allow"

            [safety.lints]
            missing-safety-docs = "deny"
        "#;

        let parsed = SniffTestConfig::from_manifest_str(config).expect("manifest should parse");

        assert_eq!(parsed.analysis.lints.empty_report_roots, LintLevel::Deny);
        assert_eq!(
            parsed.analysis.lints.ambiguous_panic_marker,
            LintLevel::Deny
        );
        assert_eq!(
            parsed.analysis.lints.ambiguous_safety_marker,
            LintLevel::Deny
        );
        assert_eq!(parsed.panics.lints.panic_invocation, LintLevel::Allow);
        assert_eq!(parsed.panics.lints.compiler_assert, LintLevel::Deny);
        assert_eq!(parsed.safety.lints.missing_safety_docs, LintLevel::Deny);
        assert_eq!(
            parsed.safety.lints.unsafe_call_missing_justification,
            LintLevel::Warn
        );
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
        let lints = AnalysisConfig::default().lints;
        assert_eq!(lints.ambiguous_panic_marker, LintLevel::Deny);
        assert_eq!(lints.ambiguous_safety_marker, LintLevel::Deny);
        assert_eq!(lints.ambiguous_panic_requirement, LintLevel::Deny);
        assert_eq!(lints.ambiguous_safety_requirement, LintLevel::Deny);
        assert_eq!(lints.panic_analysis_incomplete, LintLevel::Deny);
        assert_eq!(lints.safety_analysis_incomplete, LintLevel::Deny);
        assert_eq!(lints.empty_report_roots, LintLevel::Warn);
        assert_eq!(lints.missing_report_root, LintLevel::Warn);
    }

    #[test]
    fn default_panic_lints_keep_documented_panics_visible() {
        let lints = PanicConfig::default().lints;

        assert_eq!(lints.compiler_assert, LintLevel::Deny);
        assert_eq!(
            [
                lints.compiler_assert_bounds_check,
                lints.compiler_assert_overflow,
                lints.compiler_assert_overflow_negation,
                lints.compiler_assert_division_by_zero,
                lints.compiler_assert_remainder_by_zero,
                lints.compiler_assert_resumed_after_return,
                lints.compiler_assert_resumed_after_panic,
                lints.compiler_assert_resumed_after_drop,
                lints.compiler_assert_misaligned_pointer_dereference,
                lints.compiler_assert_null_pointer_dereference,
                lints.compiler_assert_invalid_enum_construction,
            ],
            [None; 11]
        );
        assert_eq!(lints.panic_invocation, LintLevel::Deny);
        assert_eq!(lints.documented_panic, LintLevel::Warn);
        assert_eq!(lints.unresolved_call_target, LintLevel::Allow);
    }

    #[test]
    fn unsafe_precondition_macro_is_a_user_overridable_default_ignore() {
        let defaults = PanicConfig::default();
        assert!(defaults.ignores_path("core::ub_checks::assert_unsafe_precondition"));

        let disabled = SniffTestConfig::from_manifest_str("[panics]\nignored-namespaces = []\n")
            .expect("an empty ignore list should be accepted");
        assert!(
            !disabled
                .panics
                .ignores_path("core::ub_checks::assert_unsafe_precondition")
        );
        assert!(!defaults.ignores_path("sample::assert_unsafe_precondition"));

        let replacement = SniffTestConfig::from_manifest_str(
            "[panics]\nignored-namespaces = [\"sample::generated::**\"]\n",
        )
        .expect("a custom ignore list should replace the default");
        assert!(
            replacement
                .panics
                .ignores_path("sample::generated::assert_invariant")
        );
        assert!(
            !replacement
                .panics
                .ignores_path("core::ub_checks::assert_unsafe_precondition")
        );
    }

    #[test]
    fn default_safety_lints_keep_findings_visible_without_failing() {
        let lints = SafetyConfig::default().lints;

        assert_eq!(lints.missing_safety_docs, LintLevel::Warn);
        assert_eq!(lints.unresolved_call_target, LintLevel::Allow);
        assert_eq!(lints.unsafe_call_missing_justification, LintLevel::Warn);
        assert_eq!(lints.unsafe_call_missing_requirements, LintLevel::Warn);
        assert_eq!(lints.unsafe_op_missing_justification, LintLevel::Warn);
        assert_eq!(
            [
                lints.raw_pointer_dereference_missing_justification,
                lints.mutable_static_access_missing_justification,
                lints.extern_static_access_missing_justification,
                lints.union_field_access_missing_justification,
                lints.unsafe_field_access_missing_justification,
                lints.layout_constrained_type_initialization_missing_justification,
                lints.unsafe_field_initialization_missing_justification,
                lints.layout_constrained_field_mutation_missing_justification,
                lints.layout_constrained_field_borrow_missing_justification,
                lints.inline_assembly_missing_justification,
                lints.unsafe_binder_cast_missing_justification,
            ],
            [None; 11]
        );
        assert_eq!(
            lints.safety_obligation_missing_justification,
            LintLevel::Warn
        );
        assert_eq!(
            lints.safety_obligation_missing_requirements,
            LintLevel::Warn
        );
    }

    #[test]
    fn parses_panic_lint_levels() {
        let config = r#"
            [panics.lints]
            compiler-assert = "warn"
            compiler-assert-bounds-check = "allow"
            compiler-assert-overflow = "warn"
            compiler-assert-overflow-negation = "deny"
            compiler-assert-division-by-zero = "allow"
            compiler-assert-remainder-by-zero = "warn"
            compiler-assert-resumed-after-return = "deny"
            compiler-assert-resumed-after-panic = "allow"
            compiler-assert-resumed-after-drop = "warn"
            compiler-assert-misaligned-pointer-dereference = "deny"
            compiler-assert-null-pointer-dereference = "allow"
            compiler-assert-invalid-enum-construction = "warn"
            panic-invocation = "allow"
            documented-panic = "allow"
            unresolved-call-target = "deny"
        "#;

        let parsed = SniffTestConfig::from_manifest_str(config).expect("manifest should parse");

        assert_eq!(parsed.panics.lints.compiler_assert, LintLevel::Warn);
        assert_eq!(
            [
                parsed.panics.lints.compiler_assert_bounds_check,
                parsed.panics.lints.compiler_assert_overflow,
                parsed.panics.lints.compiler_assert_overflow_negation,
                parsed.panics.lints.compiler_assert_division_by_zero,
                parsed.panics.lints.compiler_assert_remainder_by_zero,
                parsed.panics.lints.compiler_assert_resumed_after_return,
                parsed.panics.lints.compiler_assert_resumed_after_panic,
                parsed.panics.lints.compiler_assert_resumed_after_drop,
                parsed
                    .panics
                    .lints
                    .compiler_assert_misaligned_pointer_dereference,
                parsed.panics.lints.compiler_assert_null_pointer_dereference,
                parsed
                    .panics
                    .lints
                    .compiler_assert_invalid_enum_construction,
            ],
            [
                Some(LintLevel::Allow),
                Some(LintLevel::Warn),
                Some(LintLevel::Deny),
                Some(LintLevel::Allow),
                Some(LintLevel::Warn),
                Some(LintLevel::Deny),
                Some(LintLevel::Allow),
                Some(LintLevel::Warn),
                Some(LintLevel::Deny),
                Some(LintLevel::Allow),
                Some(LintLevel::Warn),
            ]
        );
        assert_eq!(parsed.panics.lints.panic_invocation, LintLevel::Allow);
        assert_eq!(parsed.panics.lints.documented_panic, LintLevel::Allow);
        assert_eq!(parsed.panics.lints.unresolved_call_target, LintLevel::Deny);
    }

    #[test]
    fn safety_configuration_preserves_namespace_and_lint_policy() {
        let config = r#"
            [safety]
            ignored-namespaces = ["bindgen::**", "my_crate::ffi"]
            trusted-boundary-namespaces = ["ffi::safe_contract", "ffi::safe_method"]

            [safety.lints]
            missing-safety-docs = "allow"
            unsafe-call-missing-justification = "deny"
            unsafe-call-missing-requirements = "allow"
            unsafe-op-missing-justification = "deny"
            safety-obligation-missing-justification = "allow"
            safety-obligation-missing-requirements = "deny"
            unresolved-call-target = "deny"
        "#;

        let parsed = SniffTestConfig::from_manifest_str(config).expect("manifest should parse");

        assert!(parsed.safety.ignores_candidates(&candidates(&[
            "my_crate::caller",
            "bindgen::root::unsafe_fn",
        ])));
        assert!(
            !parsed
                .safety
                .ignores_candidates(&candidates(&["my_crate::safe"]))
        );
        assert!(
            parsed
                .safety
                .trusts_safety_boundary_candidates(&candidates(&["ffi::safe_contract"]))
        );
        assert!(
            !parsed
                .safety
                .trusts_safety_boundary_candidates(&candidates(&["ffi::plain_safe"]))
        );
        assert_eq!(parsed.safety.lints.missing_safety_docs, LintLevel::Allow);
        assert_eq!(
            parsed.safety.lints.unsafe_call_missing_justification,
            LintLevel::Deny
        );
        assert_eq!(
            parsed.safety.lints.unsafe_call_missing_requirements,
            LintLevel::Allow
        );
        assert_eq!(
            parsed.safety.lints.unsafe_op_missing_justification,
            LintLevel::Deny
        );
        assert_eq!(
            parsed.safety.lints.safety_obligation_missing_justification,
            LintLevel::Allow
        );
        assert_eq!(
            parsed.safety.lints.safety_obligation_missing_requirements,
            LintLevel::Deny
        );
        assert_eq!(parsed.safety.lints.unresolved_call_target, LintLevel::Deny);
    }

    #[test]
    fn parses_safety_operation_lint_overrides() {
        let config = r#"
            [safety.lints]
            raw-pointer-dereference-missing-justification = "allow"
            mutable-static-access-missing-justification = "warn"
            extern-static-access-missing-justification = "deny"
            union-field-access-missing-justification = "allow"
            unsafe-field-access-missing-justification = "warn"
            layout-constrained-type-initialization-missing-justification = "deny"
            unsafe-field-initialization-missing-justification = "allow"
            layout-constrained-field-mutation-missing-justification = "warn"
            layout-constrained-field-borrow-missing-justification = "deny"
            inline-assembly-missing-justification = "allow"
            unsafe-binder-cast-missing-justification = "warn"
        "#;

        let parsed = SniffTestConfig::from_manifest_str(config).expect("manifest should parse");
        let lints = parsed.safety.lints;
        assert_eq!(
            [
                lints.raw_pointer_dereference_missing_justification,
                lints.mutable_static_access_missing_justification,
                lints.extern_static_access_missing_justification,
                lints.union_field_access_missing_justification,
                lints.unsafe_field_access_missing_justification,
                lints.layout_constrained_type_initialization_missing_justification,
                lints.unsafe_field_initialization_missing_justification,
                lints.layout_constrained_field_mutation_missing_justification,
                lints.layout_constrained_field_borrow_missing_justification,
                lints.inline_assembly_missing_justification,
                lints.unsafe_binder_cast_missing_justification,
            ],
            [
                Some(LintLevel::Allow),
                Some(LintLevel::Warn),
                Some(LintLevel::Deny),
                Some(LintLevel::Allow),
                Some(LintLevel::Warn),
                Some(LintLevel::Deny),
                Some(LintLevel::Allow),
                Some(LintLevel::Warn),
                Some(LintLevel::Deny),
                Some(LintLevel::Allow),
                Some(LintLevel::Warn),
            ]
        );
    }

    #[test]
    fn optional_exact_lint_overrides_serialize_only_when_set() {
        let mut panic_lints = PanicConfig::default().lints;
        panic_lints.compiler_assert_bounds_check = Some(LintLevel::Warn);
        let serialized = toml::to_string(&panic_lints).expect("panic lint config should serialize");
        assert!(serialized.contains("compiler-assert-bounds-check = \"warn\""));
        for omitted in [
            "compiler-assert-overflow",
            "compiler-assert-overflow-negation",
            "compiler-assert-division-by-zero",
            "compiler-assert-remainder-by-zero",
            "compiler-assert-resumed-after-return",
            "compiler-assert-resumed-after-panic",
            "compiler-assert-resumed-after-drop",
            "compiler-assert-misaligned-pointer-dereference",
            "compiler-assert-null-pointer-dereference",
            "compiler-assert-invalid-enum-construction",
        ] {
            assert!(
                !serialized.contains(omitted),
                "serialized unset panic override `{omitted}`"
            );
        }

        let mut safety_lints = SafetyConfig::default().lints;
        safety_lints.inline_assembly_missing_justification = Some(LintLevel::Deny);
        let serialized =
            toml::to_string(&safety_lints).expect("safety lint config should serialize");
        assert!(serialized.contains("inline-assembly-missing-justification = \"deny\""));
        for omitted in [
            "raw-pointer-dereference-missing-justification",
            "mutable-static-access-missing-justification",
            "extern-static-access-missing-justification",
            "union-field-access-missing-justification",
            "unsafe-field-access-missing-justification",
            "layout-constrained-type-initialization-missing-justification",
            "unsafe-field-initialization-missing-justification",
            "layout-constrained-field-mutation-missing-justification",
            "layout-constrained-field-borrow-missing-justification",
            "unsafe-binder-cast-missing-justification",
        ] {
            assert!(
                !serialized.contains(omitted),
                "serialized unset safety override `{omitted}`"
            );
        }
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
        let config = PanicConfig {
            ignored_namespaces: path_patterns(&["generated::**"]),
            trusted_boundary_namespaces: path_patterns(&["core::**", "compat::panic"]),
            panic_sink_namespaces: path_patterns(&["core::panicking::**", "canonical::panic"]),
            ..PanicConfig::default()
        };

        assert!(config.ignores_candidates(&candidates(&["app::wrapper", "generated::helper",])));
        assert_eq!(
            config.panic_boundary_policy_candidates(&candidates(&["core::fmt::write"])),
            PanicBoundaryPolicy::TrustedBoundary
        );
        assert_eq!(
            config.panic_boundary_policy_candidates(&candidates(&["core::panicking::panic_fmt"])),
            PanicBoundaryPolicy::PanicSink
        );
        assert_eq!(
            config.panic_boundary_policy_candidates(&candidates(&[
                "compat::panic",
                "canonical::panic",
            ])),
            PanicBoundaryPolicy::PanicSink,
            "equally precise sink and trusted aliases must resolve to the sink"
        );
        assert_eq!(
            config.panic_boundary_policy_candidates(&candidates(&["app::run"])),
            PanicBoundaryPolicy::Normal
        );
    }

    #[test]
    fn example_manifest_matches_direct_panic_and_ignored_macro_paths() {
        let config = SniffTestConfig::from_manifest_str(EXAMPLE_MANIFEST)
            .expect("example manifest should parse");

        assert!(
            config
                .panics
                .ignores_path("core::ub_checks::assert_unsafe_precondition")
        );
        assert_eq!(
            config
                .panics
                .panic_boundary_policy_candidates(&candidates(&["core::std::rt::panic_fmt"])),
            PanicBoundaryPolicy::PanicSink
        );
    }

    #[test]
    fn manifest_validates_namespace_globs() {
        let config = r#"
            [panics]
            panic-sink-namespaces = ["std::ops::{Index"]
        "#;

        let error = SniffTestConfig::from_manifest_str(config)
            .expect_err("invalid glob patterns should be rejected");

        assert!(error.to_string().contains("error parsing glob"));
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
