//! Apply verified, additive annotations to an ephemeral analysis artifact.
//! Cached compiler facts and dependency files are never changed.
use crate::artifact::*;
use crate::effects::EffectMetadata;
use sniff_test_report::{OverrideAnnotation, OverrideSelector};

/// Portable Cargo package identity and package-relative source filename.
pub fn package_source(filename: &str) -> Option<(String, String)> {
    thread_local! {
        static CACHE: std::cell::RefCell<std::collections::HashMap<String, Option<(String,String)>>> = std::cell::RefCell::new(std::collections::HashMap::new());
    }
    CACHE.with_borrow_mut(|cache| {
        cache
            .entry(filename.into())
            .or_insert_with(|| read_package_source(filename))
            .clone()
    })
}
fn read_package_source(filename: &str) -> Option<(String, String)> {
    let path = std::path::Path::new(filename).canonicalize().ok()?;
    for directory in path.parent()?.ancestors() {
        let manifest = directory.join("Cargo.toml");
        if !manifest.is_file() {
            continue;
        }
        let value: toml::Value = toml::from_str(&std::fs::read_to_string(manifest).ok()?).ok()?;
        let package = value.get("package")?;
        let name = package.get("name")?.as_str()?;
        let version = if let Some(version) = package.get("version")?.as_str() {
            version.to_owned()
        } else {
            directory.ancestors().find_map(|ancestor| {
                let value: toml::Value =
                    toml::from_str(&std::fs::read_to_string(ancestor.join("Cargo.toml")).ok()?)
                        .ok()?;
                value
                    .get("workspace")?
                    .get("package")?
                    .get("version")?
                    .as_str()
                    .map(str::to_owned)
            })?
        };
        return Some((
            format!("{name}@{version}"),
            path.strip_prefix(directory)
                .ok()?
                .to_str()?
                .replace('\\', "/"),
        ));
    }
    None
}

pub fn call_site_key(call: &CallFact) -> String {
    serde_json::to_string(&(
        call.expanded_range
            .as_ref()
            .map(|r| (r.byte_start, r.byte_end)),
        call.target
            .function_target()
            .map(|t| t.function.def_path_hash),
        call.kind,
    ))
    .expect("serializable call identity")
}

pub fn matching_targets(
    body: &FunctionFact,
    selector: &OverrideSelector,
    effect: &str,
) -> Vec<AnnotationTargetFact> {
    let matches = |range: Option<&SourceRangeFact>| {
        range.is_some_and(|r| {
            r.file.as_str() == selector.source_id
                && r.byte_start == selector.start
                && r.byte_end == selector.end
        })
    };
    if selector.kind == "function" {
        return matches(body.source_range.as_ref())
            .then_some(AnnotationTargetFact::Function(body.function))
            .into_iter()
            .collect();
    }
    if selector.kind == "call" {
        let calls = body
            .calls
            .iter()
            .filter(|c| {
                matches!(
                    c.kind,
                    CallKindFact::DirectCall | CallKindFact::TailCall | CallKindFact::IndirectCall
                ) && matches(c.source_range.as_ref())
                    && selector
                        .site
                        .as_ref()
                        .is_some_and(|site| *site == call_site_key(c))
            })
            .collect::<Vec<_>>();
        if calls
            .iter()
            .map(|c| c.call_site)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != 1
        {
            return vec![];
        }
        return calls
            .into_iter()
            .map(|c| AnnotationTargetFact::Call(c.id))
            .collect();
    }
    body.effects
        .iter()
        .filter(|e| {
            e.effect.as_str() == effect
                && selector.kind == format!("operation:{}", e.kind.as_str())
                && matches(e.source_range.as_ref())
        })
        .map(|e| AnnotationTargetFact::Effect(e.id))
        .collect()
}

pub fn apply(
    artifact: &mut ArtifactFacts,
    annotations: &[OverrideAnnotation],
    effects: &[EffectMetadata],
) -> Result<(), String> {
    for annotation in annotations {
        let mut selector = annotation.selector.clone();
        let Some(effect) = effects.iter().find(|e| e.key.as_str() == annotation.effect) else {
            continue;
        };
        let candidate_files = artifact
            .source_files
            .iter()
            .filter(|f| {
                package_source(&f.filename).as_ref()
                    == Some(&(selector.package.clone(), selector.source_path.clone()))
            })
            .collect::<Vec<_>>();
        let files = candidate_files
            .iter()
            .filter(|f| f.content_hash == selector.source_hash)
            .collect::<Vec<_>>();
        let definitions = artifact
            .functions
            .iter()
            .filter(|body| {
                (body.function.def_path_hash.to_string() == selector.definition
                    || body.display_path == selector.namespace)
                    && body
                        .source_range
                        .as_ref()
                        .is_some_and(|r| candidate_files.iter().any(|f| f.id == r.file))
            })
            .map(|body| body.function.def_path_hash)
            .collect::<std::collections::BTreeSet<_>>();
        if definitions.is_empty() {
            if artifact
                .functions
                .iter()
                .any(|b| b.display_path == selector.namespace)
                || !candidate_files.is_empty()
            {
                return Err(format!(
                    "stale override for {}: target changed",
                    selector.namespace
                ));
            }
            continue;
        }
        if definitions.len() != 1 || files.len() != 1 {
            return Err(format!(
                "stale or ambiguous override for {}: dependency source changed",
                selector.namespace
            ));
        }
        selector.source_id = files[0].id.as_str().to_owned();
        let bodies = artifact
            .functions
            .iter_mut()
            .filter(|b| definitions.contains(&b.function.def_path_hash))
            .collect::<Vec<_>>();
        let contract = annotation.action == "obligation";
        if !(contract && selector.kind == "function"
            || annotation.action == "justification" && selector.kind != "function")
        {
            return Err("invalid override action/target".into());
        }
        let summary = crate::contracts::contract_doc_summary_from_markdown(
            &annotation
                .document
                .lines()
                .map(|l| {
                    l.trim_start()
                        .strip_prefix("///")
                        .map_or(l, |text| text.strip_prefix(' ').unwrap_or(text))
                })
                .collect::<Vec<_>>()
                .join("\n"),
            effect.obligation,
        );
        let justification = if contract {
            None
        } else {
            crate::source_markers::override_justifications(&annotation.document, effects)?
                .unwrap_or_default()
                .into_iter()
                .find_map(|(key, parsed)| (key == effect.key).then_some(parsed))
        };
        let satisfactions = justification
            .as_ref()
            .map_or(&[][..], |parsed| parsed.satisfactions.as_slice());
        if contract && !summary.has_docs || !contract && satisfactions.is_empty() {
            return Err(format!(
                "override for {} has no valid documentation",
                selector.namespace
            ));
        }
        let mut matched = false;
        for body in bodies {
            let targets = matching_targets(body, &selector, &annotation.effect);
            if targets.is_empty() {
                continue;
            }
            if selector.kind.starts_with("operation:") && targets.len() != 1 {
                return Err(format!("ambiguous override for {}", selector.namespace));
            }
            matched = true;
            for target in targets {
                let mut next =
                    u32::try_from(body.markers.len()).map_err(|_| "too many annotations")?;
                while body.markers.iter().any(|m| m.id == MarkerId::new(next)) {
                    next = next.checked_add(1).ok_or("too many annotations")?;
                }
                let marker = AnnotationFact {
                    id: MarkerId::new(next),
                    identity: format!(
                        "audit-override:{}:{}:{}",
                        annotation.effect,
                        annotation.action,
                        serde_json::to_string(&annotation.selector).map_err(|e| e.to_string())?
                    ),
                    kind: AnnotationFactKind::new(
                        effect.key.clone(),
                        if contract {
                            AnnotationRole::Contract
                        } else {
                            AnnotationRole::Justification
                        },
                    ),
                    source_range: Some(SourceRangeFact {
                        file: SourceFileId::new(&selector.source_id),
                        byte_start: selector.start,
                        byte_end: selector.end,
                    }),
                    target,
                    applicable_probing: vec![
                        AnnotationProbingFact::SourceCallsite,
                        AnnotationProbingFact::MacroDefinitionFirst,
                    ],
                    justification_count: justification
                        .as_ref()
                        .map_or(0, |parsed| parsed.justification_count),
                    satisfactions: satisfactions
                        .iter()
                        .map(|s| AnnotationSatisfactionFact {
                            requirement: s.requirement.clone(),
                            reason: s.reason.clone(),
                            structural_path: s.path.clone(),
                        })
                        .collect(),
                    requirements: summary
                        .requirements
                        .iter()
                        .map(|r| ContractRequirementFact {
                            name: r.name.clone(),
                            condition: r.condition.clone(),
                            structural_path: r.path.clone(),
                            source_range: None,
                        })
                        .collect(),
                };
                body.markers.push(marker);
            }
        }
        if !matched {
            return Err(format!(
                "stale or ambiguous override target for {}",
                selector.namespace
            ));
        }
    }
    Ok(())
}
