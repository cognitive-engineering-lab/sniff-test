//! Shared override-file schema and source-selector validation.
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverrideFile {
    #[serde(default)]
    pub overrides: OverrideEntries,
}
#[derive(Debug, Clone, Default, Deserialize)]
pub struct OverrideEntries {
    #[serde(default)]
    pub crates: BTreeMap<String, BTreeMap<String, BTreeMap<String, String>>>,
    #[serde(flatten)]
    pub namespaces: BTreeMap<String, String>,
}

/// Exact package source location used to select synthetic rustdoc markdown.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceContractSelector {
    crate_name: String,
    version: String,
    path: String,
    start_line: u32,
    end_line: u32,
}

impl SourceContractSelector {
    /// Parses a package-relative `path:start:end` source selector.
    ///
    /// Line numbers are one-based and inclusive.
    pub fn parse(
        crate_name: impl Into<String>,
        version: impl Into<String>,
        location: &str,
    ) -> Result<Self, SourceContractSelectorError> {
        let crate_name = crate_name.into();
        Self::validate_crate_name(&crate_name)?;

        let version = version.into();
        Self::validate_version(&version)?;

        let Some((path_and_start, end_line)) = location.rsplit_once(':') else {
            return Err(SourceContractSelectorError::Location(location.to_owned()));
        };
        let Some((path, start_line)) = path_and_start.rsplit_once(':') else {
            return Err(SourceContractSelectorError::Location(location.to_owned()));
        };
        if !is_portable_source_path(path) {
            return Err(SourceContractSelectorError::Path(path.to_owned()));
        }

        let line_range = format!("{start_line}:{end_line}");
        let Ok(start_line) = start_line.parse::<u32>() else {
            return Err(SourceContractSelectorError::LineRange(line_range));
        };
        let Ok(end_line) = end_line.parse::<u32>() else {
            return Err(SourceContractSelectorError::LineRange(line_range));
        };
        if start_line == 0 || start_line > end_line {
            return Err(SourceContractSelectorError::LineRange(line_range));
        }

        Ok(Self {
            crate_name,
            version,
            path: path.to_owned(),
            start_line,
            end_line,
        })
    }

    pub fn validate_crate_name(crate_name: &str) -> Result<(), SourceContractSelectorError> {
        if is_valid_crate_name(crate_name) {
            Ok(())
        } else {
            Err(SourceContractSelectorError::CrateName(
                crate_name.to_owned(),
            ))
        }
    }

    pub fn validate_version(version: &str) -> Result<(), SourceContractSelectorError> {
        if version.trim() == version && semver::Version::parse(version).is_ok() {
            Ok(())
        } else {
            Err(SourceContractSelectorError::Version(version.to_owned()))
        }
    }

    #[must_use]
    pub fn crate_name(&self) -> &str {
        &self.crate_name
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub const fn start_line(&self) -> u32 {
        self.start_line
    }

    #[must_use]
    pub const fn end_line(&self) -> u32 {
        self.end_line
    }
}

fn is_valid_crate_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|first| {
        (first.is_ascii_alphabetic() || first == b'_')
            && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceContractSelectorError {
    CrateName(String),
    Version(String),
    Location(String),
    Path(String),
    LineRange(String),
}

impl Display for SourceContractSelectorError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CrateName(name) => write!(formatter, "invalid Rust crate name `{name}`"),
            Self::Version(version) => {
                write!(formatter, "invalid exact Cargo package version `{version}`")
            }
            Self::Location(location) => write!(
                formatter,
                "invalid source location `{location}`; expected path:start:end"
            ),
            Self::Path(path) => {
                write!(formatter, "invalid package-relative source path `{path}`")
            }
            Self::LineRange(range) => write!(
                formatter,
                "invalid source line range `{range}`; expected positive start:end"
            ),
        }
    }
}

impl std::error::Error for SourceContractSelectorError {}

#[must_use]
pub fn is_portable_source_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains(['\\', ':'])
        && path
            .split('/')
            .all(|segment| !segment.is_empty() && !matches!(segment, "." | ".."))
}
