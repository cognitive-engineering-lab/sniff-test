//! Segment-aware glob matching for Rust definition paths.

use std::borrow::Cow;
use std::fmt::{Debug, Formatter};

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use rustc_hir::def_id::DefId;
use rustc_middle::ty::TyCtxt;
use serde::{Deserialize, de::Error as _};

use crate::namespace::namespace_candidates;

/// Segment-aware glob patterns over Rust-style `::` paths.
#[derive(Clone, Default)]
pub(crate) struct PathPatterns {
    patterns: Vec<String>,
    /// Compiled glob index back to the configured pattern it came from.
    /// Recursive patterns compile to two globs (see [`PathPatterns::new`]).
    glob_pattern_indices: Vec<usize>,
    set: Option<GlobSet>,
}

impl PathPatterns {
    /// Compiles path patterns.
    ///
    /// A recursive pattern `x::**` also matches the namespace root `x` itself,
    /// so trusting or ignoring a crate does not require listing both forms.
    ///
    /// # Errors
    ///
    /// Returns an error if any configured glob pattern is invalid.
    pub(crate) fn new(patterns: Vec<String>) -> Result<Self, globset::Error> {
        if patterns.is_empty() {
            return Ok(Self {
                patterns,
                glob_pattern_indices: Vec::new(),
                set: None,
            });
        }

        let mut set = GlobSetBuilder::new();
        let mut glob_pattern_indices = Vec::new();
        for (index, pattern) in patterns.iter().enumerate() {
            set.add(
                GlobBuilder::new(normalized_path(pattern).as_ref())
                    .literal_separator(true)
                    .build()?,
            );
            glob_pattern_indices.push(index);

            if let Some(root) = pattern.strip_suffix("::**")
                && !root.is_empty()
            {
                set.add(
                    GlobBuilder::new(normalized_path(root).as_ref())
                        .literal_separator(true)
                        .build()?,
                );
                glob_pattern_indices.push(index);
            }
        }

        Ok(Self {
            patterns,
            glob_pattern_indices,
            set: Some(set.build()?),
        })
    }

    #[must_use]
    pub(crate) fn matching_pattern(&self, path: &str) -> Option<&str> {
        self.best_match(path).map(|matched| matched.pattern)
    }

    #[must_use]
    pub(crate) fn best_match(&self, path: &str) -> Option<PathPatternMatch<'_>> {
        let set = self.set.as_ref()?;
        let path = normalized_path(path);
        set.matches(path.as_ref())
            .into_iter()
            .map(|index| {
                let pattern = self.patterns[self.glob_pattern_indices[index]].as_str();
                PathPatternMatch {
                    pattern,
                    precision: pattern_precision(pattern),
                }
            })
            .max_by_key(|matched| matched.precision)
    }

    #[must_use]
    pub(crate) fn best_def_match(
        &self,
        tcx: TyCtxt<'_>,
        def_id: DefId,
    ) -> Option<PathPatternMatch<'_>> {
        namespace_candidates(tcx, def_id)
            .iter()
            .filter_map(|candidate| self.best_match(candidate))
            .max_by_key(|matched| matched.precision)
    }

    #[must_use]
    pub(crate) fn matching_def_pattern(&self, tcx: TyCtxt<'_>, def_id: DefId) -> Option<&str> {
        self.best_def_match(tcx, def_id)
            .map(|matched| matched.pattern)
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) fn is_match(&self, path: &str) -> bool {
        let Some(set) = &self.set else {
            return false;
        };
        set.is_match(normalized_path(path).as_ref())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PathPatternMatch<'patterns> {
    pub(crate) pattern: &'patterns str,
    pub(crate) precision: usize,
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

fn pattern_precision(pattern: &str) -> usize {
    pattern
        .split("::")
        .filter(|segment| !segment.is_empty() && *segment != "**")
        .count()
}
