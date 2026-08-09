//! Segment-aware glob matching for Rust definition paths.

use std::borrow::Cow;
use std::fmt::{Debug, Formatter};

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use serde::{Deserialize, de::Error as _};

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
    pub(crate) fn best_candidates_match(
        &self,
        candidates: &[String],
    ) -> Option<PathPatternMatch<'_>> {
        candidates
            .iter()
            .filter_map(|candidate| self.best_match(candidate))
            .max_by_key(|matched| matched.precision)
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

#[cfg(test)]
mod tests {
    use super::PathPatterns;

    #[test]
    fn candidate_paths_match_recursive_roots_and_prefer_specific_patterns() {
        let patterns = PathPatterns::new(vec![
            String::from("dependency::**"),
            String::from("dependency::Widget::run"),
        ])
        .expect("valid patterns");

        assert_eq!(
            patterns
                .best_candidates_match(&[String::from("dependency")])
                .map(|matched| matched.pattern),
            Some("dependency::**")
        );

        let candidates = vec![
            String::from("dependency"),
            String::from("dependency::impls::{impl#0}::run"),
            String::from("dependency::Widget::run"),
        ];

        assert_eq!(
            patterns
                .best_candidates_match(&candidates)
                .map(|matched| matched.pattern),
            Some("dependency::Widget::run")
        );
    }
}
