//! Source-local marker injections applied after loading policy-neutral caches.

use std::collections::BTreeMap;

use rustc_span::source_map::SourceMap;

use crate::artifact::{
    AnnotationFact, AnnotationFactKind, AnnotationProbingFact, AnnotationRole,
    AnnotationSatisfactionFact, AnnotationTargetFact, ArtifactFacts, EffectKey, MarkerId,
    SourceFileFact, SourceFileId, SourceRangeFact,
};
use crate::compiler::source::CachedSourceMap;
use crate::contracts::SourceContractSelector;
use crate::source_markers::OverrideJustifications;
use crate::source_overrides::{ContractSourceArtifact, SourceOverrideError, describe_selector};

#[derive(Default)]
pub(crate) struct SourceJustificationOverrides {
    by_crate: BTreeMap<u64, BTreeMap<SourceFileId, Vec<SourceJustification>>>,
}

struct SourceJustification {
    justification_count: usize,
    identity: String,
    range: SourceRangeFact,
    effect: EffectKey,
    satisfactions: Vec<AnnotationSatisfactionFact>,
}

impl SourceJustificationOverrides {
    pub(crate) fn resolve(
        source_map: &SourceMap,
        entries: Vec<(SourceContractSelector, OverrideJustifications)>,
        artifacts: &[ContractSourceArtifact<'_>],
    ) -> Result<Self, SourceOverrideError> {
        let sources = CachedSourceMap::new(source_map);
        let mut index = Self::default();
        for (selector, markers) in entries {
            for (owner, source) in matching_sources(&selector, artifacts)? {
                let range = selected_lines(source_map, &sources, source, &selector)?;
                let entries = index
                    .by_crate
                    .entry(owner)
                    .or_default()
                    .entry(source.id.clone())
                    .or_default();
                for (effect, parsed) in &markers {
                    if entries.iter().any(|entry| {
                        entry.effect == *effect
                            && entry.range.byte_start < range.byte_end
                            && range.byte_start < entry.range.byte_end
                    }) {
                        return Err(SourceOverrideError::new(format!(
                            "overlapping justification overrides for {} at {}",
                            effect.as_str(),
                            describe_selector(&selector)
                        )));
                    }
                    entries.push(SourceJustification {
                        justification_count: parsed.justification_count,
                        identity: format!(
                            "source-justification|{owner:016x}|{}|{}",
                            describe_selector(&selector),
                            effect.as_str()
                        ),
                        range: range.clone(),
                        effect: effect.clone(),
                        satisfactions: parsed
                            .satisfactions
                            .iter()
                            .map(|satisfaction| AnnotationSatisfactionFact {
                                requirement: satisfaction.requirement.clone(),
                                reason: satisfaction.reason.clone(),
                                structural_path: satisfaction.path.clone(),
                            })
                            .collect(),
                    });
                }
            }
        }
        Ok(index)
    }

    /// Looks up each call/effect in the small per-file override index.
    pub(crate) fn apply(&self, artifact: &mut ArtifactFacts) -> Result<(), SourceOverrideError> {
        if self.by_crate.is_empty() {
            return Ok(());
        }
        for body in &mut artifact.functions {
            let owner = body.function.def_path_hash.stable_crate_id();
            if !self.by_crate.contains_key(&owner) {
                continue;
            }
            let mut selected = Vec::new();
            for call in &body.calls {
                for entry in self.for_anchors(
                    owner,
                    call.marker_anchor_ranges
                        .iter()
                        .chain(call.source_range.iter()),
                ) {
                    selected.push((AnnotationTargetFact::Call(call.id), entry));
                }
            }
            for effect in &body.effects {
                for entry in self
                    .for_anchors(
                        owner,
                        effect
                            .marker_anchor_ranges
                            .iter()
                            .chain(effect.source_range.iter()),
                    )
                    .into_iter()
                    .filter(|entry| entry.effect == effect.effect)
                {
                    selected.push((AnnotationTargetFact::Effect(effect.id), entry));
                }
            }
            let next_id = body
                .markers
                .iter()
                .map(|marker| marker.id.index())
                .max()
                .map_or(0, |id| u64::from(id) + 1);
            for (offset, (target, entry)) in selected.into_iter().enumerate() {
                let id =
                    u32::try_from(next_id + u64::try_from(offset).expect("marker index fits u64"))
                        .map_err(|_| {
                            SourceOverrideError::new("too many injected markers in one function")
                        })?;
                let kind =
                    AnnotationFactKind::new(entry.effect.clone(), AnnotationRole::Justification);
                body.unverified_marker_probes
                    .retain(|probe| probe.kind != kind || probe.target != target);
                body.markers.push(AnnotationFact {
                    justification_count: entry.justification_count,
                    id: MarkerId::new(id),
                    identity: entry.identity.clone(),
                    kind,
                    source_range: Some(entry.range.clone()),
                    target,
                    applicable_probing: vec![
                        AnnotationProbingFact::SourceCallsite,
                        AnnotationProbingFact::MacroDefinitionFirst,
                    ],
                    satisfactions: entry.satisfactions.clone(),
                    requirements: Vec::new(),
                });
            }
        }
        Ok(())
    }

    fn at(
        &self,
        owner: u64,
        range: Option<&SourceRangeFact>,
    ) -> impl Iterator<Item = &SourceJustification> {
        range.into_iter().flat_map(move |range| {
            self.by_crate
                .get(&owner)
                .and_then(|files| files.get(&range.file))
                .into_iter()
                .flatten()
                .filter(move |entry| {
                    (entry.range.byte_start..entry.range.byte_end).contains(&range.byte_start)
                })
        })
    }

    /// Keep only the first matching anchor for each effect. A method-specific
    /// override therefore shadows a broader call/statement override locally.
    fn for_anchors<'a>(
        &'a self,
        owner: u64,
        anchors: impl IntoIterator<Item = &'a SourceRangeFact>,
    ) -> Vec<&'a SourceJustification> {
        let mut selected = BTreeMap::new();
        for anchor in anchors {
            for entry in self.at(owner, Some(anchor)) {
                selected.entry(&entry.effect).or_insert(entry);
            }
        }
        selected.into_values().collect()
    }
}

fn matching_sources<'a>(
    selector: &SourceContractSelector,
    artifacts: &[ContractSourceArtifact<'a>],
) -> Result<Vec<(u64, &'a SourceFileFact)>, SourceOverrideError> {
    let matching = artifacts
        .iter()
        .filter(|artifact| artifact.crate_name == selector.crate_name())
        .collect::<Vec<_>>();
    if matching
        .iter()
        .any(|artifact| artifact.package_version.is_none())
    {
        return Err(SourceOverrideError::new(format!(
            "cannot resolve justification override {} because the matching crate's package version is unavailable",
            describe_selector(selector)
        )));
    }
    let sources = matching
        .into_iter()
        .filter(|artifact| artifact.package_version == Some(selector.version()))
        .flat_map(|artifact| {
            artifact
                .facts
                .source_files
                .iter()
                .map(move |source| (artifact.stable_crate_id, source))
        })
        .filter(|(_, source)| source.logical_path.as_deref() == Some(selector.path()))
        .collect::<Vec<_>>();
    if let Some(first) = sources.first()
        && sources.iter().any(|(_, source)| {
            source.content_hash != first.1.content_hash || source.byte_len != first.1.byte_len
        })
    {
        return Err(SourceOverrideError::new(format!(
            "justification override {} matched different source contents",
            describe_selector(selector)
        )));
    }
    Ok(sources
        .into_iter()
        .map(|(owner, source)| ((owner, &source.id), (owner, source)))
        .collect::<BTreeMap<_, _>>()
        .into_values()
        .collect())
}

fn selected_lines(
    source_map: &SourceMap,
    sources: &CachedSourceMap<'_>,
    source: &SourceFileFact,
    selector: &SourceContractSelector,
) -> Result<SourceRangeFact, SourceOverrideError> {
    let point = SourceRangeFact {
        file: source.id.clone(),
        byte_start: 0,
        byte_end: 0,
    };
    let span = sources.span(source, &point).map_err(|error| {
        SourceOverrideError::new(format!(
            "cannot resolve justification override {}: {error}",
            describe_selector(selector)
        ))
    })?;
    let file = source_map.lookup_source_file(span.lo());
    let start = usize::try_from(selector.start_line() - 1).expect("source line fits usize");
    let end = usize::try_from(selector.end_line() - 1).expect("source line fits usize");
    if file.get_line(start).is_none() || file.get_line(end).is_none() {
        return Err(SourceOverrideError::new(format!(
            "justification override {} is outside the source file",
            describe_selector(selector)
        )));
    }
    Ok(SourceRangeFact {
        file: source.id.clone(),
        byte_start: u64::from((file.line_bounds(start).start - file.start_pos).0),
        byte_end: u64::from((file.line_bounds(end).end - file.start_pos).0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{
        EffectFact, EffectId, EffectKind, FunctionAttributesFact, FunctionFact,
        FunctionFactProvenance, FunctionId, StableDefPathHash, UnverifiedMarkerProbeFact,
        UnverifiedMarkerProbeReason,
    };
    use crate::compiler::source::stable_source_file_id;
    use rustc_span::source_map::FilePathMapping;

    fn with_source(check: impl FnOnce(&SourceMap, &SourceFileFact)) {
        rustc_span::create_default_session_globals_then(|| {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("lib.rs");
            std::fs::write(&path, "// α\r\nfirst();\r\nsecond();\r\n").unwrap();
            let map = SourceMap::new(FilePathMapping::empty());
            let file = map.load_file(&path).unwrap();
            let source = SourceFileFact {
                id: stable_source_file_id(&file),
                filename: path.to_string_lossy().into_owned(),
                logical_path: Some(String::from("src/lib.rs")),
                content_hash: file.src_hash.to_string(),
                byte_len: u64::from(file.normalized_source_len.0),
            };
            check(&map, &source);
        });
    }

    fn configured(location: &str, text: &str) -> (SourceContractSelector, OverrideJustifications) {
        let effects = crate::effects::selected_effects(&crate::effects::EffectSelection::default());
        (
            SourceContractSelector::parse("sample", "1.2.3", location).unwrap(),
            crate::source_markers::override_justifications(text, &effects)
                .unwrap()
                .unwrap(),
        )
    }

    fn effect_body(source: &SourceFileFact, crate_id: u64) -> FunctionFact {
        let hash: StableDefPathHash =
            serde_json::from_str(&format!("\"{crate_id:016x}0000000000000001\"")).unwrap();
        FunctionFact {
            function: FunctionId::generic(hash),
            provenance: FunctionFactProvenance::DefiningArtifact,
            behavioral_provenance_crates: Vec::new(),
            display_path: format!("sample_{crate_id}::function"),
            attributes: FunctionAttributesFact {
                is_unsafe: false,
                is_exported: true,
                has_rust_body: true,
                is_foreign: false,
                namespace_candidates: vec![format!("sample_{crate_id}::function")],
            },
            contract_declaration: None,
            source_range: None,
            calls: Vec::new(),
            effects: vec![EffectFact {
                marker_anchor_ranges: Vec::new(),
                id: EffectId::new(0),
                effect: EffectKey::new("panic"),
                effect_group: None,
                source_range: Some(SourceRangeFact {
                    file: source.id.clone(),
                    byte_start: 6,
                    byte_end: 13,
                }),
                expanded_range: None,
                macro_expansions: Vec::new(),
                kind: EffectKind::new("division-by-zero"),
            }],
            markers: Vec::new(),
            unverified_marker_probes: Vec::new(),
        }
    }

    #[test]
    fn injected_effects_use_the_first_matching_anchor_after_cache_round_trip() {
        with_source(|map, source| {
            let mut body = effect_body(source, 1);
            body.effects[0].marker_anchor_ranges = vec![
                SourceRangeFact {
                    file: source.id.clone(),
                    byte_start: 15,
                    byte_end: 24,
                },
                body.effects[0].source_range.clone().unwrap(),
            ];
            let facts = ArtifactFacts::new(vec![body], vec![source.clone()]).unwrap();
            let serialized = serde_json::to_string(&facts).unwrap();
            let mut facts: ArtifactFacts = serde_json::from_str(&serialized).unwrap();
            facts.validate().unwrap();
            let index = SourceJustificationOverrides::resolve(
                map,
                vec![
                    configured("src/lib.rs:2:2", "PANIC: broad"),
                    configured("src/lib.rs:3:3", "PANIC: specific"),
                ],
                &[ContractSourceArtifact::new(
                    1,
                    "sample",
                    Some("1.2.3"),
                    &facts,
                )],
            )
            .unwrap();
            index.apply(&mut facts).unwrap();
            let markers = &facts.functions[0].markers;
            assert_eq!(markers.len(), 1);
            assert_eq!(markers[0].satisfactions[0].reason, "specific");
            facts.validate().unwrap();
        });
    }

    #[test]
    fn injection_preserves_fact_validation_when_source_probe_was_unverified() {
        with_source(|map, source| {
            let mut body = effect_body(source, 1);
            body.unverified_marker_probes
                .push(UnverifiedMarkerProbeFact {
                    kind: AnnotationFactKind::new(
                        EffectKey::new("panic"),
                        AnnotationRole::Justification,
                    ),
                    target: AnnotationTargetFact::Effect(EffectId::new(0)),
                    probing: AnnotationProbingFact::SourceCallsite,
                    reason: UnverifiedMarkerProbeReason::SourceUnavailable,
                });
            let mut facts = ArtifactFacts::new(vec![body], vec![source.clone()]).unwrap();
            let artifact = ContractSourceArtifact::new(1, "sample", Some("1.2.3"), &facts);
            let index = SourceJustificationOverrides::resolve(
                map,
                vec![configured("src/lib.rs:2:2", "PANIC: inspected")],
                &[artifact],
            )
            .unwrap();
            index.apply(&mut facts).unwrap();
            facts
                .validate()
                .expect("injected presence must replace unverified probe state");
        });
    }

    #[test]
    fn injection_does_not_leak_between_crates_sharing_the_same_source_file() {
        with_source(|map, source| {
            let selected = effect_body(source, 1);
            let other = effect_body(source, 2);
            let mut consumer = selected.clone();
            consumer.function = FunctionId::exact(
                selected.function.def_path_hash,
                serde_json::from_str("\"00000000000000000000000000000001\"").unwrap(),
            );
            consumer.provenance = FunctionFactProvenance::ConsumerInstantiation {
                consumer_stable_crate_id: 2,
            };
            let selected_facts =
                ArtifactFacts::new(vec![selected.clone()], vec![source.clone()]).unwrap();
            let artifact = ContractSourceArtifact::new(1, "sample", Some("1.2.3"), &selected_facts);
            let index = SourceJustificationOverrides::resolve(
                map,
                vec![configured("src/lib.rs:2:2", "PANIC: inspected")],
                &[artifact],
            )
            .unwrap();
            let mut composed =
                ArtifactFacts::new(vec![selected, consumer, other], vec![source.clone()]).unwrap();
            index.apply(&mut composed).unwrap();
            assert_eq!(composed.functions[0].markers.len(), 1);
            assert_eq!(
                composed.functions[1].markers.len(),
                1,
                "consumer instantiations use definition ownership"
            );
            assert!(
                composed.functions[2].markers.is_empty(),
                "same file must not bypass crate/version selection"
            );
        });
    }

    #[test]
    fn source_lines_use_normalized_utf8_offsets_and_select_only_site_starts() {
        with_source(|map, source| {
            let facts = ArtifactFacts::new(Vec::new(), vec![source.clone()]).unwrap();
            let artifact = ContractSourceArtifact::new(1, "sample", Some("1.2.3"), &facts);
            let index = SourceJustificationOverrides::resolve(
                map,
                vec![configured("src/lib.rs:2:2", "PANIC: inspected")],
                &[artifact],
            )
            .unwrap();
            let range = |start| SourceRangeFact {
                file: source.id.clone(),
                byte_start: start,
                byte_end: start + 1,
            };
            assert_eq!(index.at(1, Some(&range(6))).count(), 1);
            assert_eq!(index.at(1, Some(&range(15))).count(), 0);
            assert_eq!(index.at(1, Some(&range(0))).count(), 0);
            assert_eq!(index.at(1, None).count(), 0);
            let entry = index.at(1, Some(&range(6))).next().unwrap();
            assert_eq!(entry.range.byte_start, 6);
        });
    }

    #[test]
    fn inactive_selectors_do_not_inject_and_unknown_package_versions_fail_closed() {
        with_source(|map, source| {
            let facts = ArtifactFacts::new(Vec::new(), vec![source.clone()]).unwrap();
            for (name, version, path) in [
                ("other", Some("1.2.3"), "src/lib.rs"),
                ("sample", Some("2.0.0"), "src/lib.rs"),
                ("sample", Some("1.2.3"), "src/unloaded.rs"),
            ] {
                let artifact = ContractSourceArtifact::new(1, name, version, &facts);
                let index = SourceJustificationOverrides::resolve(
                    map,
                    vec![configured(&format!("{path}:2:2"), "PANIC: inspected")],
                    &[artifact],
                )
                .unwrap();
                assert!(index.by_crate.is_empty());
            }
            let artifact = ContractSourceArtifact::new(1, "sample", None, &facts);
            let error = SourceJustificationOverrides::resolve(
                map,
                vec![configured("src/lib.rs:2:2", "PANIC: inspected")],
                &[artifact],
            )
            .err()
            .unwrap();
            assert!(error.to_string().contains("package version is unavailable"));
        });
    }

    #[test]
    fn invalid_lines_and_overlaps_fail_closed_while_unused_sites_remain_inactive() {
        with_source(|map, source| {
            let mut facts = ArtifactFacts::new(Vec::new(), vec![source.clone()]).unwrap();
            let artifact = ContractSourceArtifact::new(1, "sample", Some("1.2.3"), &facts);
            let error = SourceJustificationOverrides::resolve(
                map,
                vec![configured("src/lib.rs:2:99", "PANIC: inspected")],
                &[artifact],
            )
            .err()
            .unwrap();
            assert!(error.to_string().contains("outside the source file"));
            let error = SourceJustificationOverrides::resolve(
                map,
                vec![
                    configured("src/lib.rs:1:2", "PANIC: inspected"),
                    configured("src/lib.rs:2:3", "PANIC: second"),
                ],
                &[artifact],
            )
            .err()
            .unwrap();
            assert!(
                error
                    .to_string()
                    .contains("overlapping justification overrides")
            );
            let index = SourceJustificationOverrides::resolve(
                map,
                vec![configured("src/lib.rs:2:2", "PANIC: inspected")],
                &[artifact],
            )
            .unwrap();
            index
                .apply(&mut facts)
                .expect("unused markers do not force extraction of bodies or effects");
        });
    }

    #[test]
    fn stale_or_missing_selected_source_is_never_used_for_injection() {
        with_source(|map, source| {
            let mut stale = source.clone();
            stale.content_hash = String::from("stale");
            let facts = ArtifactFacts::new(Vec::new(), vec![stale]).unwrap();
            let artifact = ContractSourceArtifact::new(1, "sample", Some("1.2.3"), &facts);
            let error = SourceJustificationOverrides::resolve(
                map,
                vec![configured("src/lib.rs:2:2", "PANIC: inspected")],
                &[artifact],
            )
            .err()
            .unwrap();
            assert!(error.to_string().contains("content hash"));
            std::fs::remove_file(&source.filename).unwrap();
            let facts = ArtifactFacts::new(Vec::new(), vec![source.clone()]).unwrap();
            let artifact = ContractSourceArtifact::new(1, "sample", Some("1.2.3"), &facts);
            let fresh_map = SourceMap::new(FilePathMapping::empty());
            let error = SourceJustificationOverrides::resolve(
                &fresh_map,
                vec![configured("src/lib.rs:2:2", "PANIC: inspected")],
                &[artifact],
            )
            .err()
            .unwrap();
            assert!(error.to_string().contains("unavailable"));
        });
    }
}
