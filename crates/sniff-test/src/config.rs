//! Configuration parsing and matching.
//!
//! The public config stores user-facing TOML values. Namespace and function
//! patterns are compiled during parsing so MIR traversal can query policy
//! without rebuilding matchers for every edge.
//!
//! Path patterns treat `::` as a separator. For example, `std` matches only
//! the crate namespace root, `std::*` matches one segment under `std`, and
//! `std::**` matches recursively. Use Rust crate names in patterns, such as
//! `proc_macro2`, not package names like `proc-macro2`.

use std::borrow::Cow;
use std::fmt::{Debug, Display, Formatter};
use std::path::{Path, PathBuf};

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use serde::{Deserialize, de::Error as _};

pub const DEFAULT_MANIFEST_FILE: &str = "sniff-test.toml";
pub const EXAMPLE_MANIFEST: &str = r#"# sniff-test configuration.
#
# The default configuration leaves all policy lists empty. This example includes
# recommended Rust panic sinks and can be edited to match your threat model.

[panics]
show-full-stack-trace = false
trust-current-crate-panic-docs = "trust"
report-roots = "public"

# Crates or fully-qualified functions whose internals should be treated as
# opaque analysis boundaries. Patterns use Rust crate/path names: write
# `proc_macro2`, not the package name `proc-macro2`.
ignored-namespaces = [
    "syn", "syn::**",
    "quote", "quote::**",
    "proc_macro2", "proc_macro2::**",
    "rustc*", "rustc*::**",
]

# Caller crates or fully-qualified functions whose internal panic obligations
# you trust.
trusted-panic-obligation-namespaces = ["std::**", "core::**", "alloc::**"]

# Callees that should be treated as direct panic sinks.
panic-sink-namespaces = [
    "core::panicking::**",
    "std::panicking::**",
    "std::rt::panic_fmt",
    "core::{option,result}::unwrap_failed",
    "std::{option,result}::unwrap_failed",
]

# Callees that should be treated as panic-obligation boundaries even without
# a `# Panics` doc heading.
panic-obligation-functions = [
    "std::ops::{Index,IndexMut}::**",
]

"#;

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SniffTestConfig {
    #[serde(default)]
    pub panics: PanicConfig,
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
        Self::from_manifest_str(&source).map_err(|source| ConfigError::Parse {
            path: path.to_owned(),
            source,
        })
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
#[serde(default)]
pub struct PanicConfig {
    /// Whether detailed reports include every edge in the triggering trace.
    pub show_full_stack_trace: bool,
    /// Whether `# Panics` docs on current-crate roots satisfy their own panic evidence.
    pub trust_current_crate_panic_docs: TrustPolicy,
    /// Namespaces whose internals are treated as opaque and suppressed.
    pub ignored_namespaces: PathPatterns,
    /// Caller namespaces trusted to satisfy documented panic obligations they call.
    pub trusted_panic_obligation_namespaces: PathPatterns,
    /// Callee paths treated as direct panic sinks.
    pub panic_sink_namespaces: PathPatterns,
    /// Callee function paths treated as panic-obligation boundaries.
    pub panic_obligation_functions: PathPatterns,
    /// Current-crate functions selected as report roots.
    pub report_roots: ReportRootSet,
}

impl Default for PanicConfig {
    fn default() -> Self {
        Self {
            show_full_stack_trace: false,
            trust_current_crate_panic_docs: TrustPolicy::Trust,
            ignored_namespaces: PathPatterns::default(),
            trusted_panic_obligation_namespaces: PathPatterns::default(),
            panic_sink_namespaces: PathPatterns::default(),
            panic_obligation_functions: PathPatterns::default(),
            report_roots: ReportRootSet::Public,
        }
    }
}

impl PanicConfig {
    #[must_use]
    pub fn ignores_namespace(&self, namespace: &str) -> bool {
        self.ignored_namespaces.is_match(namespace)
    }

    #[must_use]
    pub fn ignored_namespace_match<'patterns>(
        &'patterns self,
        namespace: &str,
    ) -> Option<&'patterns str> {
        self.ignored_namespaces.matching_pattern(namespace)
    }

    #[must_use]
    pub fn trusts_panic_obligation_namespace(&self, namespace: &str) -> bool {
        self.trusted_panic_obligation_namespaces.is_match(namespace)
    }

    #[must_use]
    pub fn marks_panic_sink_namespace(&self, namespace: &str) -> bool {
        self.panic_sink_namespaces.is_match(namespace)
    }

    #[must_use]
    pub fn marks_panic_obligation_function(&self, function_path: &str) -> bool {
        self.panic_obligation_functions.is_match(function_path)
    }
}

/// Segment-aware glob patterns over Rust-style `::` paths.
#[derive(Clone, Default)]
pub struct PathPatterns {
    patterns: Vec<String>,
    set: Option<GlobSet>,
}

impl PathPatterns {
    /// Compiles path patterns.
    ///
    /// # Errors
    ///
    /// Returns an error if any configured glob pattern is invalid.
    pub fn new(patterns: Vec<String>) -> Result<Self, globset::Error> {
        if patterns.is_empty() {
            return Ok(Self {
                patterns,
                set: None,
            });
        }

        let mut set = GlobSetBuilder::new();
        for pattern in &patterns {
            set.add(
                GlobBuilder::new(normalized_path(pattern).as_ref())
                    .literal_separator(true)
                    .build()?,
            );
        }

        let set = Some(set.build()?);
        Ok(Self { patterns, set })
    }

    #[must_use]
    pub fn matching_pattern(&self, path: &str) -> Option<&str> {
        let set = self.set.as_ref()?;

        let path = normalized_path(path);
        set.matches(path.as_ref())
            .into_iter()
            .next()
            .map(|index| self.patterns[index].as_str())
    }

    #[must_use]
    pub fn is_match(&self, path: &str) -> bool {
        let Some(set) = &self.set else {
            return false;
        };

        let path = normalized_path(path);
        set.is_match(path.as_ref())
    }
}

impl Debug for PathPatterns {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        self.patterns.fmt(formatter)
    }
}

impl PartialEq for PathPatterns {
    fn eq(&self, other: &Self) -> bool {
        self.patterns == other.patterns
    }
}

impl Eq for PathPatterns {}

impl<'de> Deserialize<'de> for PathPatterns {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let patterns = Vec::<String>::deserialize(deserializer)?;
        Self::new(patterns).map_err(D::Error::custom)
    }
}

fn normalized_path(path: &str) -> Cow<'_, str> {
    if path.contains("::") {
        Cow::Owned(path.replace("::", "/"))
    } else {
        Cow::Borrowed(path)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustPolicy {
    #[default]
    Trust,
    Verify,
}

/// Current-crate functions whose reachable panic paths should be reported.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ReportRootSet {
    /// Report from public exported functions.
    #[default]
    Public,
    /// Report from every local function.
    All,
    /// Report from these fully qualified current-crate function paths.
    Explicit(Vec<String>),
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
                while let Some(path) = seq.next_element::<String>()? {
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
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Parse { source, .. } => Some(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PanicConfig, PathPatterns, ReportRootSet, SniffTestConfig};

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
    fn rejects_old_split_namespace_fields() {
        let config = r#"
            [panics]
            ignored-crates = ["syn"]
        "#;

        let error = SniffTestConfig::from_manifest_str(config)
            .expect_err("old split namespace fields should be rejected");

        assert!(error.to_string().contains("unknown field `ignored-crates`"));
    }

    #[test]
    fn trusted_panic_obligation_namespace_patterns_match_exact_names_paths_and_globs() {
        let config = PanicConfig {
            trusted_panic_obligation_namespaces: path_patterns(&[
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

        assert!(config.trusts_panic_obligation_namespace("std"));
        assert!(!config.trusts_panic_obligation_namespace("std::io::Error::new"));
        assert!(config.trusts_panic_obligation_namespace("std::io"));
        assert!(config.trusts_panic_obligation_namespace("alloc::vec::Vec::push"));
        assert!(config.trusts_panic_obligation_namespace("rustc_middle::ty::TyCtxt"));
        assert!(!config.trusts_panic_obligation_namespace("rustc_middle"));
        assert!(config.trusts_panic_obligation_namespace("smallvec"));
        assert!(config.trusts_panic_obligation_namespace("serde_json"));
        assert!(
            config.trusts_panic_obligation_namespace("core::char::methods::from_u32_unchecked")
        );
        assert!(!config.trusts_panic_obligation_namespace("rustix"));
        assert!(!config.trusts_panic_obligation_namespace("smallalloc"));
        assert!(!config.trusts_panic_obligation_namespace("serde_core"));
        assert!(!config.trusts_panic_obligation_namespace("core::char::methods::from_u32"));
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
    fn function_patterns_match_segmented_def_paths() {
        let config = PanicConfig {
            panic_obligation_functions: path_patterns(&["std::ops::{Index,IndexMut}::**"]),
            ..PanicConfig::default()
        };

        assert!(config.marks_panic_obligation_function("std::ops::Index::index"));
        assert!(config.marks_panic_obligation_function("std::ops::IndexMut::index_mut"));
        assert!(!config.marks_panic_obligation_function("std::option::Option<T>::unwrap"));
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
    fn rejects_invalid_glob_patterns() {
        let config = r#"
            [panics]
            panic-obligation-functions = ["std::ops::{Index"]
        "#;

        let error = SniffTestConfig::from_manifest_str(config)
            .expect_err("invalid glob patterns should be rejected");

        assert!(error.to_string().contains("error parsing glob"));
    }

    #[test]
    fn parses_report_roots() {
        let all = r#"
            [panics]
            report-roots = "all"
        "#;
        let explicit = r#"
            [panics]
            report-roots = ["test::a", "test::b"]
        "#;

        let parsed_all = SniffTestConfig::from_manifest_str(all).expect("manifest should parse");
        let parsed_explicit =
            SniffTestConfig::from_manifest_str(explicit).expect("manifest should parse");
        assert_eq!(parsed_all.panics.report_roots, ReportRootSet::All);
        assert_eq!(
            parsed_explicit.panics.report_roots,
            ReportRootSet::Explicit(vec![String::from("test::a"), String::from("test::b")])
        );
    }
}
