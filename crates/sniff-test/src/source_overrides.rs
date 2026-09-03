//! Resolution of source-located synthetic contract documentation.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::artifact::{
    ArtifactFacts, DefinitionSourceFact, SourceFileFact, SourceRangeFact, StableDefPathHash,
};
use crate::contracts::{ContractDocOverrides, SourceContractSelector};
use crate::workspace::ArtifactAnalysisGraph;

/// Crate/version provenance paired with the policy-neutral facts it owns.
#[derive(Clone, Copy)]
pub(crate) struct ContractSourceArtifact<'a> {
    stable_crate_id: u64,
    crate_name: &'a str,
    package_version: Option<&'a str>,
    facts: &'a ArtifactFacts,
}

impl<'a> ContractSourceArtifact<'a> {
    #[must_use]
    pub(crate) const fn new(
        stable_crate_id: u64,
        crate_name: &'a str,
        package_version: Option<&'a str>,
        facts: &'a ArtifactFacts,
    ) -> Self {
        Self {
            stable_crate_id,
            crate_name,
            package_version,
            facts,
        }
    }
}

/// One source override after it has been resolved to a stable definition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedSourceContractOverride {
    selector: SourceContractSelector,
    markdown: String,
    source_range: SourceRangeFact,
}

impl ResolvedSourceContractOverride {
    #[must_use]
    pub(crate) fn markdown(&self) -> &str {
        &self.markdown
    }

    #[must_use]
    pub(crate) const fn source_range(&self) -> &SourceRangeFact {
        &self.source_range
    }
}

/// Resolves source selectors across the local artifact and every loaded dependency.
pub(crate) fn resolve_source_contract_overrides(
    overrides: &ContractDocOverrides,
    local: ContractSourceArtifact<'_>,
    dependencies: &ArtifactAnalysisGraph,
) -> Result<BTreeMap<StableDefPathHash, ResolvedSourceContractOverride>, SourceOverrideError> {
    let mut artifacts = Vec::with_capacity(dependencies.artifacts().count() + 1);
    artifacts.push(local);
    artifacts.extend(dependencies.artifacts().map(|dependency| {
        ContractSourceArtifact::new(
            dependency.artifact.id.stable_crate_id,
            &dependency.artifact.crate_name,
            dependency.artifact.package_version.as_deref(),
            &dependency.facts,
        )
    }));
    resolve_source_contract_overrides_for_artifacts(overrides, &artifacts)
}

fn resolve_source_contract_overrides_for_artifacts(
    overrides: &ContractDocOverrides,
    artifacts: &[ContractSourceArtifact<'_>],
) -> Result<BTreeMap<StableDefPathHash, ResolvedSourceContractOverride>, SourceOverrideError> {
    let mut resolved = BTreeMap::<StableDefPathHash, ResolvedSourceContractOverride>::new();
    for (selector, markdown) in overrides.source_entries() {
        let candidates = candidates_for_source_override(selector, artifacts)?;
        for candidate in candidates {
            if let Some(previous) = resolved.get(&candidate.definition.definition) {
                return Err(SourceOverrideError::new(format!(
                    "overlapping source overrides {} and {} both match `{}`",
                    describe_selector(&previous.selector),
                    describe_selector(selector),
                    candidate.definition.display_path
                )));
            }
            resolved.insert(
                candidate.definition.definition,
                ResolvedSourceContractOverride {
                    selector: selector.clone(),
                    markdown: markdown.to_owned(),
                    source_range: candidate.definition.source_range.clone(),
                },
            );
        }
    }
    Ok(resolved)
}

fn candidates_for_source_override<'facts>(
    selector: &SourceContractSelector,
    artifacts: &[ContractSourceArtifact<'facts>],
) -> Result<Vec<DefinitionCandidate<'facts>>, SourceOverrideError> {
    let matching_crates = artifacts
        .iter()
        .copied()
        .filter(|artifact| artifact.crate_name == selector.crate_name())
        .collect::<Vec<_>>();
    if matching_crates.is_empty() {
        return Ok(Vec::new());
    }
    if matching_crates
        .iter()
        .any(|artifact| artifact.package_version.is_none())
    {
        return Err(SourceOverrideError::new(format!(
            "cannot resolve source override {} because the matching crate's package version is unavailable",
            describe_selector(selector)
        )));
    }
    let matching_artifacts = matching_crates
        .into_iter()
        .filter(|artifact| artifact.package_version == Some(selector.version()))
        .collect::<Vec<_>>();
    if matching_artifacts.is_empty() {
        return Ok(Vec::new());
    }

    let path_sources = matching_artifacts
        .iter()
        .flat_map(|artifact| {
            artifact
                .facts
                .source_files
                .iter()
                .filter(|source| source.logical_path.as_deref() == Some(selector.path()))
        })
        .collect::<Vec<_>>();
    if path_sources.is_empty() {
        return Ok(Vec::new());
    }
    let content_versions = path_sources
        .iter()
        .map(|source| (source.content_hash.clone(), source.byte_len))
        .collect::<BTreeSet<_>>();
    if content_versions.len() != 1 {
        return Err(SourceOverrideError::new(format!(
            "source override {} matched different source contents",
            describe_selector(selector)
        )));
    }

    let candidates = matching_artifacts
        .iter()
        .flat_map(|artifact| {
            artifact
                .facts
                .definitions
                .iter()
                .filter_map(move |definition| {
                    definition_in_selector(artifact.facts, definition, selector).map(|source| {
                        DefinitionCandidate {
                            artifact: *artifact,
                            definition,
                            source,
                        }
                    })
                })
        })
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return Err(SourceOverrideError::new(format!(
            "source override {} matched no definition",
            describe_selector(selector)
        )));
    }
    if !candidates_are_equivalent(&candidates) {
        return Err(SourceOverrideError::new(format!(
            "source override {} matched multiple definitions: {}",
            describe_selector(selector),
            describe_candidates(&candidates)
        )));
    }
    Ok(candidates)
}

fn candidates_are_equivalent(candidates: &[DefinitionCandidate<'_>]) -> bool {
    let equivalence_classes = candidates
        .iter()
        .map(DefinitionCandidate::equivalence_key)
        .collect::<BTreeSet<_>>();
    let definitions_per_artifact = candidates.iter().fold(
        BTreeMap::<u64, BTreeSet<StableDefPathHash>>::new(),
        |mut definitions, candidate| {
            definitions
                .entry(candidate.artifact.stable_crate_id)
                .or_default()
                .insert(candidate.definition.definition);
            definitions
        },
    );
    equivalence_classes.len() == 1
        && definitions_per_artifact
            .values()
            .all(|definitions| definitions.len() == 1)
}

fn definition_in_selector<'a>(
    artifact: &'a ArtifactFacts,
    definition: &DefinitionSourceFact,
    selector: &SourceContractSelector,
) -> Option<&'a SourceFileFact> {
    if !(selector.start_line()..=selector.end_line()).contains(&definition.start_line) {
        return None;
    }
    artifact.source_files.iter().find(|source| {
        source.id == definition.source_range.file
            && source.logical_path.as_deref() == Some(selector.path())
    })
}

struct DefinitionCandidate<'a> {
    artifact: ContractSourceArtifact<'a>,
    definition: &'a DefinitionSourceFact,
    source: &'a SourceFileFact,
}

impl DefinitionCandidate<'_> {
    fn equivalence_key(&self) -> DefinitionEquivalenceKey<'_> {
        DefinitionEquivalenceKey {
            display_path: &self.definition.display_path,
            start_line: self.definition.start_line,
            byte_start: self.definition.source_range.byte_start,
            byte_end: self.definition.source_range.byte_end,
            content_hash: &self.source.content_hash,
            byte_len: self.source.byte_len,
        }
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct DefinitionEquivalenceKey<'a> {
    display_path: &'a str,
    start_line: u32,
    byte_start: u64,
    byte_end: u64,
    content_hash: &'a str,
    byte_len: u64,
}

fn describe_selector(selector: &SourceContractSelector) -> String {
    format!(
        "`{}:{}/{}:{}:{}`",
        selector.crate_name(),
        selector.version(),
        selector.path(),
        selector.start_line(),
        selector.end_line()
    )
}

fn describe_candidates(candidates: &[DefinitionCandidate<'_>]) -> String {
    let mut descriptions = candidates
        .iter()
        .map(|candidate| {
            format!(
                "`{}` at {}:{}",
                candidate.definition.display_path,
                candidate
                    .source
                    .logical_path
                    .as_deref()
                    .unwrap_or("<unknown>"),
                candidate.definition.start_line
            )
        })
        .collect::<Vec<_>>();
    descriptions.sort();
    descriptions.dedup();
    descriptions.join(", ")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SourceOverrideError {
    message: String,
}

impl SourceOverrideError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for SourceOverrideError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for SourceOverrideError {}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{ContractSourceArtifact, resolve_source_contract_overrides_for_artifacts};
    use crate::artifact::{
        ArtifactFacts, DefinitionSourceFact, SourceFileFact, SourceFileId, SourceRangeFact,
        StableDefPathHash,
    };
    use crate::contracts::{ContractDocOverrides, SourceContractSelector};

    fn definition(stable_crate_id: u64, local_hash: u64) -> StableDefPathHash {
        serde_json::from_str(&format!("\"{stable_crate_id:016x}{local_hash:016x}\""))
            .expect("stable definition hash")
    }

    fn source_range(file: &SourceFileId, start: u64, end: u64) -> SourceRangeFact {
        SourceRangeFact {
            file: file.clone(),
            byte_start: start,
            byte_end: end,
        }
    }

    fn facts(
        stable_crate_id: u64,
        path: &str,
        content_hash: &str,
        definitions: &[(&str, u64, u32, u64, u64)],
    ) -> ArtifactFacts {
        let file = SourceFileId::new(format!("source-{stable_crate_id}"));
        ArtifactFacts::with_definitions(
            Vec::new(),
            vec![SourceFileFact {
                id: file.clone(),
                filename: format!("/checkout/{stable_crate_id}/{path}"),
                logical_path: Some(path.to_owned()),
                content_hash: content_hash.to_owned(),
                byte_len: 4_096,
            }],
            definitions
                .iter()
                .map(
                    |(display_path, local_hash, line, start, end)| DefinitionSourceFact {
                        definition: definition(stable_crate_id, *local_hash),
                        display_path: (*display_path).to_owned(),
                        source_range: source_range(&file, *start, *end),
                        start_line: *line,
                    },
                )
                .collect(),
        )
        .expect("valid source provenance")
    }

    fn overrides(entries: &[(&str, &str, &str, &str)]) -> ContractDocOverrides {
        let source_entries = entries
            .iter()
            .map(|(crate_name, version, location, markdown)| {
                (
                    SourceContractSelector::parse(*crate_name, *version, location)
                        .expect("valid selector"),
                    (*markdown).to_owned(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        ContractDocOverrides::with_source_entries(Vec::new(), source_entries)
            .expect("no namespace globs")
    }

    #[test]
    fn source_override_selects_exact_version_and_definition_start_line() {
        let selected = facts(
            1,
            "src/lib.rs",
            "hash-a",
            &[
                ("sample::selected", 10, 12, 100, 140),
                ("sample::adjacent", 11, 20, 200, 240),
            ],
        );
        let other_version = facts(
            2,
            "src/lib.rs",
            "hash-b",
            &[("sample::selected", 10, 12, 100, 140)],
        );
        let configured = overrides(&[("sample", "1.0.0", "src/lib.rs:10:15", "# Panics")]);
        let artifacts = [
            ContractSourceArtifact::new(1, "sample", Some("1.0.0"), &selected),
            ContractSourceArtifact::new(2, "sample", Some("2.0.0"), &other_version),
        ];

        let resolved = resolve_source_contract_overrides_for_artifacts(&configured, &artifacts)
            .expect("one exact source definition should resolve");

        assert_eq!(resolved.len(), 1);
        assert_eq!(
            resolved
                .get(&definition(1, 10))
                .expect("selected definition")
                .markdown(),
            "# Panics"
        );
        assert!(!resolved.contains_key(&definition(1, 11)));
        assert!(!resolved.contains_key(&definition(2, 10)));

        for inactive in [
            overrides(&[("absent", "1.0.0", "src/lib.rs:1:1", "# Panics")]),
            overrides(&[("sample", "3.0.0", "src/lib.rs:1:1", "# Panics")]),
        ] {
            assert!(
                resolve_source_contract_overrides_for_artifacts(&inactive, &artifacts)
                    .expect("overrides for absent crate versions stay inactive")
                    .is_empty()
            );
        }
    }

    #[test]
    fn equivalent_source_mirrors_receive_the_same_override() {
        let first = facts(
            1,
            "src/lib.rs",
            "same-hash",
            &[("sample::selected", 10, 12, 100, 140)],
        );
        let second = facts(
            2,
            "src/lib.rs",
            "same-hash",
            &[("sample::selected", 10, 12, 100, 140)],
        );
        let configured = overrides(&[("sample", "1.0.0", "src/lib.rs:12:12", "# Safety")]);
        let artifacts = [
            ContractSourceArtifact::new(1, "sample", Some("1.0.0"), &first),
            ContractSourceArtifact::new(2, "sample", Some("1.0.0"), &second),
        ];

        let resolved = resolve_source_contract_overrides_for_artifacts(&configured, &artifacts)
            .expect("byte-identical mirrors should be equivalent");

        assert_eq!(resolved.len(), 2);
        assert!(resolved.contains_key(&definition(1, 10)));
        assert!(resolved.contains_key(&definition(2, 10)));
    }

    #[test]
    fn artifacts_without_the_selected_path_or_definition_are_inactive() {
        let selected = facts(
            1,
            "src/lib.rs",
            "same-hash",
            &[("sample::selected", 10, 12, 100, 140)],
        );
        let configured = overrides(&[("sample", "1.0.0", "src/lib.rs:12:12", "# Safety")]);

        for mirror in [
            facts(
                2,
                "src/other.rs",
                "same-hash",
                &[("sample::selected", 10, 12, 100, 140)],
            ),
            facts(
                2,
                "src/lib.rs",
                "same-hash",
                &[("sample::selected", 10, 20, 100, 140)],
            ),
        ] {
            let artifacts = [
                ContractSourceArtifact::new(1, "sample", Some("1.0.0"), &selected),
                ContractSourceArtifact::new(2, "sample", Some("1.0.0"), &mirror),
            ];

            let resolved = resolve_source_contract_overrides_for_artifacts(&configured, &artifacts)
                .expect("crate targets and cfg variants without this definition are unrelated");

            assert_eq!(resolved.len(), 1);
            assert!(resolved.contains_key(&definition(1, 10)));
        }
    }

    #[test]
    fn source_override_rejects_different_contents_for_one_logical_source() {
        let first = facts(
            1,
            "src/lib.rs",
            "hash-a",
            &[("sample::selected", 10, 12, 100, 140)],
        );
        let second = facts(
            2,
            "src/lib.rs",
            "hash-b",
            &[("sample::selected", 10, 12, 100, 140)],
        );
        let configured = overrides(&[("sample", "1.0.0", "src/lib.rs:12:12", "# Panics")]);
        let artifacts = [
            ContractSourceArtifact::new(1, "sample", Some("1.0.0"), &first),
            ContractSourceArtifact::new(2, "sample", Some("1.0.0"), &second),
        ];

        let error = resolve_source_contract_overrides_for_artifacts(&configured, &artifacts)
            .expect_err("different source contents must fail closed");

        assert!(error.to_string().contains("different source contents"));
    }

    #[test]
    fn source_override_rejects_zero_or_multiple_definition_matches() {
        let source = facts(
            1,
            "src/lib.rs",
            "hash-a",
            &[
                ("sample::first", 10, 12, 100, 140),
                ("sample::second", 11, 13, 150, 190),
            ],
        );
        let artifacts = [ContractSourceArtifact::new(
            1,
            "sample",
            Some("1.0.0"),
            &source,
        )];

        let missing = overrides(&[("sample", "1.0.0", "src/lib.rs:20:21", "# Panics")]);
        let missing_error = resolve_source_contract_overrides_for_artifacts(&missing, &artifacts)
            .expect_err("stale line selection must fail closed");
        assert!(missing_error.to_string().contains("matched no definition"));

        let ambiguous = overrides(&[("sample", "1.0.0", "src/lib.rs:12:13", "# Panics")]);
        let ambiguous_error =
            resolve_source_contract_overrides_for_artifacts(&ambiguous, &artifacts)
                .expect_err("two definitions in one line window must fail closed");
        assert!(ambiguous_error.to_string().contains("multiple definitions"));
        assert!(ambiguous_error.to_string().contains("sample::first"));
        assert!(ambiguous_error.to_string().contains("sample::second"));
    }

    #[test]
    fn source_override_handles_inactive_paths_and_rejects_unknown_versions_and_overlaps() {
        let source = facts(
            1,
            "src/lib.rs",
            "hash-a",
            &[("sample::selected", 10, 12, 100, 140)],
        );
        let versionless = [ContractSourceArtifact::new(1, "sample", None, &source)];
        let one = overrides(&[("sample", "1.0.0", "src/lib.rs:12:12", "# Panics")]);
        let version_error = resolve_source_contract_overrides_for_artifacts(&one, &versionless)
            .expect_err("an unknown matching crate version must fail closed");
        assert!(
            version_error
                .to_string()
                .contains("package version is unavailable")
        );

        let artifacts = [ContractSourceArtifact::new(
            1,
            "sample",
            Some("1.0.0"),
            &source,
        )];
        let missing_path = overrides(&[("sample", "1.0.0", "src/other.rs:1:2", "# Panics")]);
        assert!(
            resolve_source_contract_overrides_for_artifacts(&missing_path, &artifacts)
                .expect("a source path absent from this artifact is inactive")
                .is_empty()
        );

        let overlap = overrides(&[
            ("sample", "1.0.0", "src/lib.rs:10:12", "# Panics"),
            ("sample", "1.0.0", "src/lib.rs:12:15", "# Safety"),
        ]);
        let overlap_error = resolve_source_contract_overrides_for_artifacts(&overlap, &artifacts)
            .expect_err("two source selectors cannot target one definition");
        assert!(
            overlap_error
                .to_string()
                .contains("overlapping source overrides")
        );
    }
}
