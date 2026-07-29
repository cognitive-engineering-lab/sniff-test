//! Configuration parsing and matching.
//!
//! The public config stores user-facing TOML values. Namespace and function
//! patterns are compiled during parsing so MIR traversal can query policy
//! without rebuilding matchers for every edge.
//!
//! Path patterns treat `::` as a separator. For example, `std` matches only
//! the crate namespace root, `std::*` matches one segment under `std`, and
//! `std::**` matches `std` and everything beneath it. Definitions are matched
//! against every session-independent namespace form they have (crate root,
//! definition-site path, and impl self-type path — see
//! [`crate::namespace::namespace_candidates`]), so `alloc::**` also covers
//! trait-impl methods such as `<Vec<T> as Index<usize>>::index`. Use Rust
//! crate names in patterns, such as `proc_macro2`, not package names like
//! `proc-macro2`.

use std::collections::BTreeMap;
use std::fmt::{Debug, Display, Formatter};
use std::ops::Range;
use std::path::{Path, PathBuf};

use reachability::{
    DynDispatchVTableEdges as ReachabilityDynDispatchVTableEdges,
    FnPointerEdges as ReachabilityFnPointerEdges,
};
use rustc_hir::def_id::DefId;
use rustc_middle::ty::TyCtxt;
use serde::{Deserialize, Serialize};
use toml::Spanned;

use crate::contracts::ContractDocOverrides;
use crate::path_patterns::{PathPatternMatch, PathPatterns};

pub const DEFAULT_MANIFEST_FILE: &str = "sniff-test.toml";
pub const EXAMPLE_MANIFEST: &str = include_str!("../example-manifest.toml");

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SniffTestConfig {
    #[serde(default)]
    pub analysis: AnalysisConfig,
    #[serde(default)]
    pub documentation: DocumentationConfig,
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
        config.load_documentation_overrides(base_dir)?;
        Ok(config)
    }

    /// Parses a sniff-test manifest from a string.
    ///
    /// # Errors
    ///
    /// Returns an error when the manifest contains unsupported syntax.
    pub fn from_manifest_str(source: &str) -> Result<Self, toml::de::Error> {
        let mut config: Self = toml::from_str(source)?;
        config.install_documentation_overrides();
        Ok(config)
    }

    fn load_documentation_overrides(&mut self, base_dir: &Path) -> Result<(), ConfigError> {
        self.documentation.load_overrides(base_dir)?;
        self.install_documentation_overrides();
        Ok(())
    }

    fn install_documentation_overrides(&mut self) {
        self.panics.documentation_overrides = self.documentation.overrides.clone();
        self.safety.documentation_overrides = self.documentation.overrides.clone();
    }

    #[must_use]
    pub(crate) fn all_effects_ignore_namespace(&self, namespace: &str) -> bool {
        self.safety.ignores_namespace(namespace) && self.panics.ignores_namespace(namespace)
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
    /// Whether rustc should emit integer overflow and invalid-shift checks.
    pub overflow_checks: OverflowChecks,
    /// Whether rustc should perform MIR inlining before analysis.
    pub inline_mir: MirInlining,
    /// Where concrete callable targets should appear once erased behind dyn
    /// dispatch or function pointers.
    pub callable_edge_attribution: CallableEdgeAttribution,
    /// How `// PANIC:` and `// SAFETY:` comments are found for spans produced
    /// by macro expansion.
    pub marker_probing: MarkerProbing,
    /// User-facing severity for analyzer-wide finding classes.
    pub lints: AnalysisLintConfig,
    /// Instance budget per reachability query; halting at the limit is
    /// surfaced through the `analysis-incomplete` lint.
    pub node_limit: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
#[serde(default)]
pub struct DocumentationConfig {
    /// TOML files containing synthetic rustdoc markdown by namespace glob.
    pub override_files: Vec<PathBuf>,
    #[serde(skip)]
    pub overrides: ContractDocOverrides,
    #[serde(skip)]
    resolved_override_files: Vec<PathBuf>,
}

impl DocumentationConfig {
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
            overflow_checks: OverflowChecks::Profile,
            inline_mir: MirInlining::Off,
            callable_edge_attribution: CallableEdgeAttribution::ErasureSites,
            marker_probing: MarkerProbing::MacroDefinitionFirst,
            lints: AnalysisLintConfig::default(),
            node_limit: 4096,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MarkerProbing {
    /// Probe the final user callsite only. This is the historical behavior.
    SourceCallsite,
    /// Probe macro definition spans first, then macro callsites outward, then
    /// the final user callsite.
    #[default]
    MacroDefinitionFirst,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct AnalysisLintConfig {
    pub ambiguous_effect_marker: LintLevel,
    pub ambiguous_effect_requirement: LintLevel,
    pub analysis_incomplete: LintLevel,
    pub empty_report_roots: LintLevel,
    pub missing_report_root: LintLevel,
}

impl Default for AnalysisLintConfig {
    fn default() -> Self {
        Self {
            ambiguous_effect_marker: LintLevel::Deny,
            ambiguous_effect_requirement: LintLevel::Deny,
            // A truncated traversal proves nothing about the missing region.
            analysis_incomplete: LintLevel::Deny,
            empty_report_roots: LintLevel::Warn,
            missing_report_root: LintLevel::Warn,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CallableEdgeAttribution {
    /// Attribute concrete targets where callables are erased into dyn objects
    /// or function pointers.
    #[default]
    ErasureSites,
    /// Attribute concrete dyn-dispatch methods and function-pointer targets to
    /// dynamic call sites.
    CallSites,
}

impl From<CallableEdgeAttribution> for ReachabilityDynDispatchVTableEdges {
    fn from(value: CallableEdgeAttribution) -> Self {
        match value {
            CallableEdgeAttribution::ErasureSites => Self::CastSites,
            CallableEdgeAttribution::CallSites => Self::CallSites,
        }
    }
}

impl From<CallableEdgeAttribution> for ReachabilityFnPointerEdges {
    fn from(value: CallableEdgeAttribution) -> Self {
        match value {
            CallableEdgeAttribution::ErasureSites => Self::ReifySites,
            CallableEdgeAttribution::CallSites => Self::CallSites,
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
#[serde(default)]
pub struct PanicConfig {
    /// User-facing severity for panic finding classes.
    pub lints: PanicLintConfig,
    /// Namespaces whose internals are treated as opaque and suppressed.
    pub ignored_namespaces: PathPatterns,
    /// Callee namespaces whose `# Panics` documentation is trusted as complete.
    ///
    /// Matching callees are opaque: documented panic conditions become caller
    /// obligations, while undocumented callees are trusted as non-panicking.
    pub trusted_panic_boundary_namespaces: PathPatterns,
    /// Callee paths treated as direct panic sinks.
    pub panic_sink_namespaces: PathPatterns,
    #[serde(skip)]
    pub documentation_overrides: ContractDocOverrides,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct PanicLintConfig {
    pub compiler_assert: LintLevel,
    pub panic_invocation: LintLevel,
    pub cached_dependency_panic: LintLevel,
    pub documented_panic: LintLevel,
    pub trusted_panic: LintLevel,
    pub indirect_call_boundary: LintLevel,
}

impl Default for PanicLintConfig {
    fn default() -> Self {
        Self {
            compiler_assert: LintLevel::Deny,
            panic_invocation: LintLevel::Deny,
            cached_dependency_panic: LintLevel::Deny,
            documented_panic: LintLevel::Warn,
            trusted_panic: LintLevel::Warn,
            indirect_call_boundary: LintLevel::Warn,
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
    /// Callee namespaces whose `# Safety` documentation is trusted as complete.
    ///
    /// Matching callees are opaque: documented safety conditions become caller
    /// obligations, while undocumented callees are trusted as having none.
    pub trusted_safety_boundary_namespaces: PathPatterns,
    pub lints: SafetyLintConfig,
    #[serde(skip)]
    pub documentation_overrides: ContractDocOverrides,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct SafetyLintConfig {
    pub missing_safety_docs: LintLevel,
    pub unsafe_call_missing_justification: LintLevel,
    pub unsafe_call_missing_requirements: LintLevel,
    pub unsafe_op_missing_justification: LintLevel,
    pub safety_obligation_missing_justification: LintLevel,
    pub safety_obligation_missing_requirements: LintLevel,
}

impl Default for SafetyLintConfig {
    fn default() -> Self {
        Self {
            missing_safety_docs: LintLevel::Warn,
            unsafe_call_missing_justification: LintLevel::Warn,
            unsafe_call_missing_requirements: LintLevel::Warn,
            unsafe_op_missing_justification: LintLevel::Warn,
            safety_obligation_missing_justification: LintLevel::Warn,
            safety_obligation_missing_requirements: LintLevel::Warn,
        }
    }
}

impl PanicConfig {
    #[must_use]
    pub fn ignores_namespace(&self, namespace: &str) -> bool {
        self.ignored_namespace_match(namespace).is_some()
    }

    #[must_use]
    pub fn ignored_namespace_match<'patterns>(
        &'patterns self,
        namespace: &str,
    ) -> Option<&'patterns str> {
        self.ignored_namespaces.matching_pattern(namespace)
    }

    #[must_use]
    pub fn ignores_def(&self, tcx: TyCtxt<'_>, def_id: DefId) -> bool {
        self.ignored_def_match(tcx, def_id).is_some()
    }

    #[must_use]
    pub fn ignored_def_match<'patterns>(
        &'patterns self,
        tcx: TyCtxt<'_>,
        def_id: DefId,
    ) -> Option<&'patterns str> {
        self.ignored_namespaces.matching_def_pattern(tcx, def_id)
    }

    #[must_use]
    #[cfg(test)]
    fn trusts_panic_boundary_namespace(&self, namespace: &str) -> bool {
        self.trusted_panic_boundary_namespaces.is_match(namespace)
    }

    #[must_use]
    #[cfg(test)]
    fn marks_panic_sink_namespace(&self, namespace: &str) -> bool {
        self.panic_sink_namespaces.is_match(namespace)
    }

    #[must_use]
    pub fn panic_boundary_policy(&self, tcx: TyCtxt<'_>, def_id: DefId) -> PanicBoundaryPolicy {
        let sink = self.panic_sink_def_match(tcx, def_id);
        let trusted = self.trusted_panic_boundary_def_match(tcx, def_id);

        match (sink, trusted) {
            (Some(sink), Some(trusted)) if trusted.precision > sink.precision => {
                PanicBoundaryPolicy::TrustedBoundary
            }
            (Some(_), Some(_) | None) => PanicBoundaryPolicy::PanicSink,
            (None, Some(_)) => PanicBoundaryPolicy::TrustedBoundary,
            (None, None) => PanicBoundaryPolicy::Normal,
        }
    }

    fn panic_sink_def_match(&self, tcx: TyCtxt<'_>, def_id: DefId) -> Option<PathPatternMatch<'_>> {
        self.panic_sink_namespaces.best_def_match(tcx, def_id)
    }

    fn trusted_panic_boundary_def_match(
        &self,
        tcx: TyCtxt<'_>,
        def_id: DefId,
    ) -> Option<PathPatternMatch<'_>> {
        self.trusted_panic_boundary_namespaces
            .best_def_match(tcx, def_id)
    }
}

impl SafetyConfig {
    #[must_use]
    pub fn ignores_namespace(&self, namespace: &str) -> bool {
        self.ignored_namespace_match(namespace).is_some()
    }

    #[must_use]
    pub fn ignored_namespace_match<'patterns>(
        &'patterns self,
        namespace: &str,
    ) -> Option<&'patterns str> {
        self.ignored_namespaces.matching_pattern(namespace)
    }

    #[must_use]
    pub fn ignores_def(&self, tcx: TyCtxt<'_>, def_id: DefId) -> bool {
        self.ignored_def_match(tcx, def_id).is_some()
    }

    #[must_use]
    pub fn ignored_def_match<'patterns>(
        &'patterns self,
        tcx: TyCtxt<'_>,
        def_id: DefId,
    ) -> Option<&'patterns str> {
        self.ignored_namespaces.matching_def_pattern(tcx, def_id)
    }

    #[must_use]
    #[cfg(test)]
    fn trusts_safety_boundary_namespace(&self, namespace: &str) -> bool {
        self.trusted_safety_boundary_namespaces.is_match(namespace)
    }

    #[must_use]
    pub fn trusts_safety_boundary_def(&self, tcx: TyCtxt<'_>, def_id: DefId) -> bool {
        self.trusted_safety_boundary_def_match(tcx, def_id)
            .is_some()
    }

    fn trusted_safety_boundary_def_match(
        &self,
        tcx: TyCtxt<'_>,
        def_id: DefId,
    ) -> Option<PathPatternMatch<'_>> {
        self.trusted_safety_boundary_namespaces
            .best_def_match(tcx, def_id)
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
            Self::Io { path, source } => {
                write!(f, "failed to read {}: {source}", path.display())
            }
            Self::Parse { path, source } => {
                write!(f, "failed to parse {}: {source}", path.display())
            }
            Self::OverrideIo { path, source } => {
                write!(
                    f,
                    "failed to read documentation override file {}: {source}",
                    path.display()
                )
            }
            Self::OverrideParse { path, source } => {
                write!(
                    f,
                    "failed to parse documentation override file {}: {source}",
                    path.display()
                )
            }
            Self::OverrideGlob { path, source } => {
                write!(
                    f,
                    "failed to compile documentation override globs in {}: {source}",
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
        AnalysisConfig, CallableEdgeAttribution, ContractDocOverrides, EXAMPLE_MANIFEST, LintLevel,
        MarkerProbing, MirInlining, OverflowChecks, PanicConfig, PathPatterns, ReportRootSet,
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

    #[test]
    fn rejects_unknown_config_fields() {
        let error = SniffTestConfig::from_manifest_str("[analysis]\nnode-limt = 10")
            .expect_err("unknown config fields should be rejected");

        assert!(error.to_string().contains("unknown field `node-limt`"));
    }

    #[test]
    fn parses_analysis_overflow_checks() {
        let config = r#"
            [analysis]
            show-full-stack-trace = true
            report-roots = "all"
            overflow-checks = "on"
            inline-mir = "profile"
            callable-edge-attribution = "call-sites"
            marker-probing = "source-callsite"
        "#;

        let parsed = SniffTestConfig::from_manifest_str(config).expect("manifest should parse");

        assert!(parsed.analysis.show_full_stack_trace);
        assert_eq!(parsed.analysis.report_roots.get_ref(), &ReportRootSet::All);
        assert_eq!(parsed.analysis.overflow_checks, OverflowChecks::On);
        assert_eq!(parsed.analysis.inline_mir, MirInlining::Profile);
        assert_eq!(
            parsed.analysis.callable_edge_attribution,
            CallableEdgeAttribution::CallSites
        );
        assert_eq!(
            parsed.analysis.marker_probing,
            MarkerProbing::SourceCallsite
        );
    }

    #[test]
    fn parses_analysis_lint_levels() {
        let config = r#"
            [analysis.lints]
            analysis-incomplete = "warn"
            ambiguous-effect-marker = "allow"
            ambiguous-effect-requirement = "warn"
            empty-report-roots = "deny"
            missing-report-root = "allow"
        "#;

        let parsed = SniffTestConfig::from_manifest_str(config).expect("manifest should parse");

        assert_eq!(parsed.analysis.lints.analysis_incomplete, LintLevel::Warn);
        assert_eq!(
            parsed.analysis.lints.ambiguous_effect_marker,
            LintLevel::Allow
        );
        assert_eq!(
            parsed.analysis.lints.ambiguous_effect_requirement,
            LintLevel::Warn
        );
        assert_eq!(parsed.analysis.lints.empty_report_roots, LintLevel::Deny);
        assert_eq!(parsed.analysis.lints.missing_report_root, LintLevel::Allow);
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
            parsed.analysis.lints.ambiguous_effect_marker,
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
    fn default_analysis_disables_mir_inlining_for_trace_stability() {
        assert_eq!(AnalysisConfig::default().inline_mir, MirInlining::Off);
        assert_eq!(
            AnalysisConfig::default().callable_edge_attribution,
            CallableEdgeAttribution::ErasureSites
        );
        assert_eq!(
            AnalysisConfig::default().marker_probing,
            MarkerProbing::MacroDefinitionFirst
        );
        let lints = AnalysisConfig::default().lints;
        assert_eq!(lints.ambiguous_effect_marker, LintLevel::Deny);
        assert_eq!(lints.ambiguous_effect_requirement, LintLevel::Deny);
        assert_eq!(lints.analysis_incomplete, LintLevel::Deny,);
        assert_eq!(lints.empty_report_roots, LintLevel::Warn);
        assert_eq!(lints.missing_report_root, LintLevel::Warn);
    }

    #[test]
    fn default_panic_lints_keep_documented_panics_visible() {
        let lints = PanicConfig::default().lints;

        assert_eq!(lints.compiler_assert, LintLevel::Deny);
        assert_eq!(lints.panic_invocation, LintLevel::Deny);
        assert_eq!(lints.cached_dependency_panic, LintLevel::Deny);
        assert_eq!(lints.documented_panic, LintLevel::Warn);
        assert_eq!(lints.trusted_panic, LintLevel::Warn);
        assert_eq!(lints.indirect_call_boundary, LintLevel::Warn);
    }

    #[test]
    fn default_safety_lints_keep_findings_visible_without_failing() {
        let lints = SafetyConfig::default().lints;

        assert_eq!(lints.missing_safety_docs, LintLevel::Warn);
        assert_eq!(lints.unsafe_call_missing_justification, LintLevel::Warn);
        assert_eq!(lints.unsafe_call_missing_requirements, LintLevel::Warn);
        assert_eq!(lints.unsafe_op_missing_justification, LintLevel::Warn);
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
    fn dependency_is_fully_ignored_only_when_both_effects_ignore_it() {
        let mut config = SniffTestConfig::default();
        config.panics.ignored_namespaces = path_patterns(&["shared::**", "panic_only::**"]);
        config.safety.ignored_namespaces = path_patterns(&["shared::**", "safety_only::**"]);

        assert!(config.all_effects_ignore_namespace("shared::module"));
        assert!(!config.all_effects_ignore_namespace("panic_only::module"));
        assert!(!config.all_effects_ignore_namespace("safety_only::module"));
    }

    #[test]
    fn parses_panic_lint_levels() {
        let config = r#"
            [panics.lints]
            compiler-assert = "warn"
            panic-invocation = "allow"
            cached-dependency-panic = "warn"
            documented-panic = "allow"
            trusted-panic = "deny"
            indirect-call-boundary = "deny"
        "#;

        let parsed = SniffTestConfig::from_manifest_str(config).expect("manifest should parse");

        assert_eq!(parsed.panics.lints.compiler_assert, LintLevel::Warn);
        assert_eq!(parsed.panics.lints.panic_invocation, LintLevel::Allow);
        assert_eq!(parsed.panics.lints.cached_dependency_panic, LintLevel::Warn);
        assert_eq!(parsed.panics.lints.documented_panic, LintLevel::Allow);
        assert_eq!(parsed.panics.lints.trusted_panic, LintLevel::Deny);
        assert_eq!(parsed.panics.lints.indirect_call_boundary, LintLevel::Deny);
    }

    #[test]
    fn parses_safety_lint_levels() {
        let config = r#"
            [safety]
            ignored-namespaces = ["bindgen::**", "my_crate::ffi"]
            trusted-safety-boundary-namespaces = ["ffi::safe_contract", "ffi::safe_method"]

            [safety.lints]
            missing-safety-docs = "allow"
            unsafe-call-missing-justification = "deny"
            unsafe-call-missing-requirements = "allow"
            unsafe-op-missing-justification = "deny"
            safety-obligation-missing-justification = "allow"
            safety-obligation-missing-requirements = "deny"
        "#;

        let parsed = SniffTestConfig::from_manifest_str(config).expect("manifest should parse");

        assert!(
            parsed
                .safety
                .ignored_namespace_match("bindgen::root::unsafe_fn")
                .is_some()
        );
        assert!(
            parsed
                .safety
                .ignored_namespace_match("my_crate::ffi")
                .is_some()
        );
        assert!(
            parsed
                .safety
                .ignored_namespace_match("my_crate::safe")
                .is_none()
        );
        assert!(
            parsed
                .safety
                .trusts_safety_boundary_namespace("ffi::safe_contract")
        );
        assert!(
            parsed
                .safety
                .trusts_safety_boundary_namespace("ffi::safe_method")
        );
        assert!(
            !parsed
                .safety
                .trusts_safety_boundary_namespace("ffi::plain_safe")
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
    }

    #[test]
    fn rejects_ambiguous_callable_edge_attribution_both_mode() {
        let config = r#"
            [analysis]
            callable-edge-attribution = "both"
        "#;

        let error =
            SniffTestConfig::from_manifest_str(config).expect_err("manifest should be rejected");

        let message = error.to_string();
        assert!(message.contains("unknown variant `both`"));
        assert!(message.contains("erasure-sites"));
        assert!(message.contains("call-sites"));
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
    fn trusted_panic_boundary_namespace_patterns_match_exact_names_paths_and_globs() {
        let config = PanicConfig {
            trusted_panic_boundary_namespaces: path_patterns(&[
                "std",
                "std::*",
                "alloc::**",
                "rustc*::**",
                "small?ec",
                "serde_{derive,json}",
                "**::*unchecked",
            ]),
            ..PanicConfig::default()
        };

        assert!(config.trusts_panic_boundary_namespace("std"));
        assert!(!config.trusts_panic_boundary_namespace("std::io::Error::new"));
        assert!(config.trusts_panic_boundary_namespace("std::io"));
        assert!(config.trusts_panic_boundary_namespace("alloc::vec::Vec::push"));
        // Recursive patterns include the namespace root itself.
        assert!(config.trusts_panic_boundary_namespace("alloc"));
        assert!(config.trusts_panic_boundary_namespace("rustc_middle::ty::TyCtxt"));
        assert!(config.trusts_panic_boundary_namespace("rustc_middle"));
        assert!(config.trusts_panic_boundary_namespace("smallvec"));
        assert!(config.trusts_panic_boundary_namespace("serde_json"));
        assert!(config.trusts_panic_boundary_namespace("core::char::methods::from_u32_unchecked"));
        assert!(!config.trusts_panic_boundary_namespace("rustix"));
        assert!(!config.trusts_panic_boundary_namespace("smallalloc"));
        assert!(!config.trusts_panic_boundary_namespace("serde_core"));
        assert!(!config.trusts_panic_boundary_namespace("core::char::methods::from_u32"));
    }

    #[test]
    fn ignored_namespace_patterns_match_exact_names_paths_and_globs() {
        let config = PanicConfig {
            ignored_namespaces: path_patterns(&[
                "syn",
                "quote",
                "proc_macro2",
                "proc_macro2::**",
                "*_derive",
                "std::io::Error::new",
                "**::from_*_unchecked",
            ]),
            ..PanicConfig::default()
        };

        assert!(config.ignores_namespace("syn"));
        assert!(!config.ignores_namespace("syn::parse"));
        assert!(config.ignores_namespace("quote"));
        assert!(config.ignores_namespace("proc_macro2"));
        assert!(config.ignores_namespace("proc_macro2::TokenStream"));
        assert!(!config.ignores_namespace("proc-macro2"));
        assert!(config.ignores_namespace("serde_derive"));
        assert!(config.ignores_namespace("std::io::Error::new"));
        assert!(config.ignores_namespace("core::char::methods::from_u32_unchecked"));
        assert!(!config.ignores_namespace("serde"));
        assert!(!config.ignores_namespace("std::io::Error::kind"));
        assert!(!config.ignores_namespace("core::char::methods::from_u32"));
    }

    #[test]
    fn panic_sink_namespace_patterns_match_segmented_def_paths() {
        let config = PanicConfig {
            panic_sink_namespaces: path_patterns(&["core::panicking::**"]),
            ..PanicConfig::default()
        };

        assert!(config.marks_panic_sink_namespace("core::panicking::panic_fmt"));
        assert!(config.marks_panic_sink_namespace("core::panicking::panic_bounds_check"));
        assert!(!config.marks_panic_sink_namespace("core::option::unwrap_failed"));
    }

    #[test]
    fn example_manifest_matches_direct_panic_macro_path() {
        let config = SniffTestConfig::from_manifest_str(EXAMPLE_MANIFEST)
            .expect("example manifest should parse");

        assert!(
            config
                .panics
                .marks_panic_sink_namespace("core::std::rt::panic_fmt")
        );
    }

    #[test]
    fn rejects_invalid_glob_patterns() {
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
    fn parses_documentation_override_files() {
        let config = r#"
            [documentation]
            override-files = ["override.toml", "audit/zerocopy.toml"]
        "#;

        let parsed = SniffTestConfig::from_manifest_str(config).expect("manifest should parse");

        assert_eq!(
            parsed.documentation.override_files,
            [
                PathBuf::from("override.toml"),
                PathBuf::from("audit/zerocopy.toml")
            ]
        );
    }

    #[test]
    fn documentation_overrides_use_most_specific_namespace_glob() {
        let overrides = ContractDocOverrides::new(vec![
            ("zerocopy::**".to_owned(), "# Safety\n".to_owned()),
            (
                "zerocopy::Layout::for_type".to_owned(),
                "# Panics\n".to_owned(),
            ),
        ])
        .expect("override globs should compile");

        assert_eq!(
            overrides.markdown_for_namespace("zerocopy::Layout::for_type"),
            Some("# Panics\n")
        );
        assert_eq!(
            overrides.markdown_for_namespace("zerocopy::FromBytes"),
            Some("# Safety\n")
        );
    }

    #[test]
    fn manifest_loads_documentation_overrides_relative_to_itself() {
        let dir = tempfile::tempdir().expect("tempdir should be created");
        let manifest_path = dir.path().join("sniff-test.toml");
        let override_path = dir.path().join("override.toml");
        std::fs::write(
            &manifest_path,
            r#"
                [documentation]
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
            parsed.documentation.resolved_override_files(),
            std::slice::from_ref(&override_path)
        );
        assert_eq!(
            parsed
                .documentation
                .overrides
                .markdown_for_namespace("zerocopy::Layout::for_type")
                .map(str::trim),
            Some("# Panics\n\n- nonzero: layout size must be representable.")
        );
    }
}
