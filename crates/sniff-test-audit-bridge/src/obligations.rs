use super::*;

#[derive(Debug, Clone, Serialize)]
pub struct ObligationSummary {
    pub key: String,
    pub label: String,
    pub effect: String,
    pub count: usize,
    pub items: Vec<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ObligationDetail {
    pub key: String,
    pub effect: String,
    pub namespace: String,
    pub count: usize,
    pub documentation: Option<sniff_test_report::ObligationDocumentation>,
    pub declaration: Option<Location>,
    pub trusted: bool,
    pub config_path: String,
    pub config_hash: Option<String>,
    pub results_revision: u64,
}

struct ObligationTarget<'a> {
    namespace: &'a str,
    declaration: Option<&'a Location>,
}

fn target(finding: &Finding) -> Option<(&str, ObligationTarget<'_>)> {
    if finding.class.as_deref() != Some("documented-obligation") {
        return None;
    }
    let audit = finding.audit.as_ref()?;
    let namespace = audit
        .obligation_documentation
        .as_ref()
        .map(|d| d.function.as_str())
        .or_else(|| finding.direct_source.as_ref()?.target.as_deref())
        .or_else(|| audit.trace.last()?.target.as_deref())?;
    Some((
        finding.effect.as_deref()?,
        ObligationTarget {
            namespace,
            declaration: audit.contract.as_ref(),
        },
    ))
}

fn key(effect: &str, obligation: &ObligationTarget<'_>) -> String {
    // Contract provenance separates same-named functions from different dependency versions.
    // Callsite, requirement names, and report roots deliberately do not participate.
    let declaration = obligation
        .declaration
        .map(|l| (&l.path, &l.source_id, &l.hash, l.start, l.end));
    serde_json::to_string(&(effect, obligation.namespace, declaration)).unwrap()
}

/// Count report contributions rather than distinct callsites or roots.
pub fn group_obligations(findings: &[&Finding], query: &str) -> Vec<ObligationSummary> {
    let mut groups = BTreeMap::<String, ObligationSummary>::new();
    let mut matching = BTreeSet::new();
    let query = query.to_lowercase();
    for finding in findings {
        let Some((effect, obligation)) = target(finding) else {
            continue;
        };
        let key = key(effect, &obligation);
        let document = finding
            .audit
            .as_ref()
            .and_then(|a| a.obligation_documentation.as_ref());
        if format!(
            "{effect} {} {}",
            obligation.namespace,
            document.map_or("", |d| d.markdown.as_str())
        )
        .to_lowercase()
        .contains(&query)
        {
            matching.insert(key.clone());
        }
        let group = groups
            .entry(key.clone())
            .or_insert_with(|| ObligationSummary {
                key,
                label: format!("{effect} · {}", obligation.namespace),
                effect: effect.into(),
                count: 0,
                items: Vec::new(),
            });
        group.count += 1;
    }
    let mut groups: Vec<_> = groups
        .into_values()
        .filter(|g| matching.contains(&g.key))
        .collect();
    groups.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then(a.label.cmp(&b.label))
            .then(a.key.cmp(&b.key))
    });
    groups
}

impl Session {
    pub fn obligation_detail(&self, selected: &str) -> Result<ObligationDetail> {
        let reports: Vec<_> = self
            .analysis
            .findings
            .iter()
            .filter(|f| target(f).is_some_and(|(effect, o)| key(effect, &o) == selected))
            .collect();
        let first = reports
            .first()
            .context("obligation no longer exists; reanalyze")?;
        let (effect, obligation) = target(first).unwrap();
        let manifest = self.checked_override_destination(&self.override_manifest())?;
        let original = read_config(&manifest)?;
        let config = original
            .as_deref()
            .unwrap_or("")
            .parse::<toml_edit::Document>()?;
        let patterns = config
            .get(effect)
            .and_then(|t| t.get("ignored-namespaces"))
            .and_then(toml_edit::Item::as_array);
        let trusted = if let Some(patterns) = patterns {
            let mut builder = globset::GlobSetBuilder::new();
            for pattern in patterns {
                let pattern = pattern
                    .as_str()
                    .context("invalid ignored-namespaces entry")?;
                builder.add(
                    globset::GlobBuilder::new(&pattern.replace("::", "/"))
                        .literal_separator(true)
                        .build()?,
                );
                if let Some(root) = pattern.strip_suffix("::**") {
                    builder.add(
                        globset::GlobBuilder::new(&root.replace("::", "/"))
                            .literal_separator(true)
                            .build()?,
                    );
                }
            }
            builder
                .build()?
                .is_match(obligation.namespace.replace("::", "/"))
        } else {
            false
        };
        let declaration = reports
            .iter()
            .filter_map(|f| target(f)?.1.declaration)
            .max_by_key(|l| l.available)
            .cloned();
        Ok(ObligationDetail {
            key: selected.into(),
            effect: effect.into(),
            namespace: obligation.namespace.to_owned(),
            count: reports.len(),
            documentation: reports
                .iter()
                .find_map(|f| f.audit.as_ref()?.obligation_documentation.clone()),
            declaration,
            trusted,
            config_path: manifest.to_string_lossy().into_owned(),
            config_hash: original.as_ref().map(|s| content_hash(s.as_bytes())),
            results_revision: self.analysis.results_revision,
        })
    }

    pub fn trust_obligation(
        &mut self,
        selected: &str,
        results_revision: u64,
        expected_hash: Option<&str>,
    ) -> Result<ObligationDetail> {
        self.set_obligation_trust(selected, results_revision, expected_hash, true)
    }

    pub fn untrust_obligation(
        &mut self,
        selected: &str,
        results_revision: u64,
        expected_hash: Option<&str>,
    ) -> Result<ObligationDetail> {
        self.set_obligation_trust(selected, results_revision, expected_hash, false)
    }

    fn set_obligation_trust(
        &mut self,
        selected: &str,
        results_revision: u64,
        expected_hash: Option<&str>,
        trusted: bool,
    ) -> Result<ObligationDetail> {
        ensure!(!self.analysis.running, "analysis is running");
        ensure!(
            results_revision == self.analysis.results_revision,
            "obligation selection is outdated; select it again"
        );
        let detail = self.obligation_detail(selected)?;
        // A retry after a successful write is harmless, including when a broader pattern covers it.
        if trusted && detail.trusted {
            return Ok(detail);
        }
        ensure!(
            detail.config_hash.as_deref() == expected_hash,
            "configuration changed; select the obligation again"
        );
        let manifest = Path::new(&detail.config_path);
        let original = read_config(manifest)?;
        ensure!(
            original
                .as_ref()
                .map(|s| content_hash(s.as_bytes()))
                .as_deref()
                == expected_hash,
            "configuration changed; select the obligation again"
        );
        let mut config = original
            .as_deref()
            .unwrap_or("")
            .parse::<toml_edit::Document>()?;
        if config.get(&detail.effect).is_none() {
            config[&detail.effect] = toml_edit::Item::Table(toml_edit::Table::new());
        }
        ensure!(
            config[&detail.effect].as_table_like().is_some(),
            "effect configuration must be a table"
        );
        if config[&detail.effect].get("ignored-namespaces").is_none() {
            let mut defaults = toml_edit::Array::new();
            for pattern in self
                .default_ignored_namespaces
                .get(&detail.effect)
                .into_iter()
                .flatten()
            {
                defaults.push(pattern.as_str());
            }
            config[&detail.effect]["ignored-namespaces"] = toml_edit::value(defaults);
        }
        let patterns = config[&detail.effect]["ignored-namespaces"]
            .as_array_mut()
            .context("ignored-namespaces must be an array")?;
        // Namespace display paths can contain glob metacharacters, e.g. array types.
        let pattern = globset::escape(&detail.namespace);
        if trusted {
            if !patterns.iter().any(|p| p.as_str() == Some(&pattern)) {
                patterns.push(pattern);
            }
        } else {
            ensure!(
                patterns.iter().any(|p| p.as_str() == Some(&pattern)),
                "no exact trust entry exists for this function; refresh the obligation"
            );
            for index in (0..patterns.len()).rev() {
                if patterns.get(index).and_then(toml_edit::Value::as_str) == Some(&pattern) {
                    patterns.remove(index);
                }
            }
        }
        let content = config.to_string();
        // Validate before writing; reject malformed effect tables without disturbing the file.
        content.parse::<toml::Value>()?;
        ensure!(
            read_config(manifest)? == original,
            "configuration changed; select the obligation again"
        );
        atomic_write(manifest, content.as_bytes())?;
        self.analysis.override_revision += 1;
        self.analysis.overrides_changed = true;
        self.analysis.stale = true;
        self.obligation_detail(selected)
    }
}

fn read_config(path: &Path) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn finding(id: &str, effect: &str, function: &str, path: &str) -> Finding {
        serde_json::from_value(json!({
            "id":id,"crate_name":"test","effect":effect,"kind":"effect",
            "class":"documented-obligation","level":"warn","root":id,
            "reason":"contract","requirements":[id],"missing_requirements":[id],"display_trace":[],
            "audit":{
                "effect":effect,"obligation":"Contract","justification":"CHECK",
                "contract":{"path":path,"source_id":path,"hash":"hash","start":0,"end":10,"available":false},
                "obligation_documentation":{"function":function,"markdown":format!("# Contract\n{id}")},
                "trace":[],"targets":[]
            }
        })).unwrap()
    }

    #[test]
    fn groups_callsites_roots_and_requirements_but_separates_effects_and_versions() {
        let mut reports = vec![
            finding("a", "panic", "dep::push", "dep-1/lib.rs"),
            finding("b", "panic", "dep::push", "dep-1/lib.rs"),
            finding("c", "safety", "dep::push", "dep-1/lib.rs"),
            finding("d", "panic", "dep::push", "dep-2/lib.rs"),
        ];
        let mut operation = reports[0].clone();
        operation.class = Some("concrete-operation".into());
        reports.push(operation);
        let refs: Vec<_> = reports.iter().collect();
        let groups = group_obligations(&refs, "");
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0].count, 2);
        assert_eq!(groups.iter().map(|g| g.count).sum::<usize>(), 4);
        // Matching one report's documentation retains the whole definition's count.
        let matches = group_obligations(&refs, "\na");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].count, 2);
        assert!(group_obligations(&refs, "no such function").is_empty());
    }

    #[test]
    fn missing_documentation_uses_existing_target_metadata() {
        let mut report = finding("a", "custom", "dep::work", "dep/lib.rs");
        let audit = report.audit.as_mut().unwrap();
        audit.obligation_documentation = None;
        audit.trace.push(TraceStep {
            caller: "test::root".into(),
            target: Some("dep::work".into()),
            kind: sniff_test_report::TraceKind::DirectCall,
            marker_association: MarkerAssociation::SourceInvocation,
            location: None,
        });
        assert_eq!(group_obligations(&[&report], "dep::work")[0].count, 1);
    }

    #[test]
    fn trust_preserves_defaults_comments_other_effects_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let mut session = super::super::tests::session(dir.path());
        session.set_default_ignored_namespaces(BTreeMap::from([(
            "panic".into(),
            vec!["core::ub_checks::assert_unsafe_precondition".into()],
        )]));
        let path = dir.path().join("sniff-test.toml");
        fs::write(
            &path,
            "# keep me\n[safety]\nignored-namespaces = [\"other\"] # keep too\n",
        )
        .unwrap();
        session.analysis.findings = vec![finding("a", "panic", "dep::push", "dep/lib.rs")];
        let groups = group_obligations(&session.analysis.findings.iter().collect::<Vec<_>>(), "");
        let detail = session.obligation_detail(&groups[0].key).unwrap();
        let trusted = session
            .trust_obligation(
                &detail.key,
                detail.results_revision,
                detail.config_hash.as_deref(),
            )
            .unwrap();
        assert!(trusted.trusted);
        let saved = fs::read_to_string(&path).unwrap();
        assert!(saved.contains("# keep me") && saved.contains("# keep too"));
        let config: toml::Value = saved.parse().unwrap();
        assert_eq!(
            config["panic"]["ignored-namespaces"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            config["safety"]["ignored-namespaces"][0].as_str(),
            Some("other")
        );
        assert!(session.analysis.stale && session.analysis.overrides_changed);
        session
            .trust_obligation(
                &detail.key,
                detail.results_revision,
                detail.config_hash.as_deref(),
            )
            .unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), saved);
        assert!(
            session
                .untrust_obligation(
                    &detail.key,
                    detail.results_revision,
                    detail.config_hash.as_deref()
                )
                .is_err()
        );
        let removed = session
            .untrust_obligation(
                &trusted.key,
                trusted.results_revision,
                trusted.config_hash.as_deref(),
            )
            .unwrap();
        assert!(!removed.trusted);
        let after = fs::read_to_string(&path).unwrap();
        assert!(after.contains("# keep me") && after.contains("# keep too"));
        assert!(!after.contains("dep::push"));
        assert!(after.contains("core::ub_checks::assert_unsafe_precondition"));
    }

    #[test]
    fn untrust_preserves_explicit_empty_array_and_escaped_paths() {
        let dir = tempfile::tempdir().unwrap();
        let mut session = super::super::tests::session(dir.path());
        session.analysis.findings = vec![finding("a", "custom", "dep::[u8]::work", "dep/lib.rs")];
        let group = group_obligations(&[&session.analysis.findings[0]], "").remove(0);
        let detail = session.obligation_detail(&group.key).unwrap();
        let trusted = session
            .trust_obligation(
                &detail.key,
                detail.results_revision,
                detail.config_hash.as_deref(),
            )
            .unwrap();
        assert!(trusted.trusted);
        assert!(
            session
                .untrust_obligation(
                    &trusted.key,
                    trusted.results_revision + 1,
                    trusted.config_hash.as_deref()
                )
                .is_err()
        );
        session.analysis.running = true;
        assert!(
            session
                .untrust_obligation(
                    &trusted.key,
                    trusted.results_revision,
                    trusted.config_hash.as_deref()
                )
                .is_err()
        );
        session.analysis.running = false;
        let removed = session
            .untrust_obligation(
                &trusted.key,
                trusted.results_revision,
                trusted.config_hash.as_deref(),
            )
            .unwrap();
        assert!(!removed.trusted);
        let config: toml::Value = fs::read_to_string(dir.path().join("sniff-test.toml"))
            .unwrap()
            .parse()
            .unwrap();
        assert!(
            config["custom"]["ignored-namespaces"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn trust_checks_config_snapshot_generation_and_running_analysis() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("settings")).unwrap();
        let mut session = super::super::tests::session(dir.path());
        session.config.arguments = vec!["--manifest=settings/audit.toml".into()];
        session.analysis.findings = vec![finding("a", "custom", "dep::work", "dep/lib.rs")];
        let group = group_obligations(&[&session.analysis.findings[0]], "").remove(0);
        let detail = session.obligation_detail(&group.key).unwrap();
        let path = dir.path().join("settings/audit.toml");
        fs::write(&path, "# changed\n").unwrap();
        assert!(session.trust_obligation(&group.key, 0, None).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "# changed\n");
        let detail = session.obligation_detail(&detail.key).unwrap();
        assert!(
            session
                .trust_obligation(&group.key, 1, detail.config_hash.as_deref())
                .is_err()
        );
        session.analysis.running = true;
        assert!(
            session
                .trust_obligation(&group.key, 0, detail.config_hash.as_deref())
                .is_err()
        );
        session.analysis.running = false;
        session
            .trust_obligation(&group.key, 0, detail.config_hash.as_deref())
            .unwrap();
        assert!(!dir.path().join("sniff-test.toml").exists());
        let config: toml::Value = fs::read_to_string(path).unwrap().parse().unwrap();
        assert_eq!(
            config["custom"]["ignored-namespaces"][0].as_str(),
            Some("dep::work")
        );
    }

    #[test]
    fn invalid_configuration_is_never_overwritten() {
        for original in [
            "panic = 3\n",
            "[panic]\nignored-namespaces=3\n",
            "[panic]\nignored-namespaces=[3]\n",
            "not valid toml",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let mut session = super::super::tests::session(dir.path());
            let path = dir.path().join("sniff-test.toml");
            fs::write(&path, original).unwrap();
            session.analysis.findings = vec![finding("a", "panic", "dep::push", "dep/lib.rs")];
            let group = group_obligations(&[&session.analysis.findings[0]], "").remove(0);
            let hash = content_hash(original.as_bytes());
            assert!(
                session
                    .trust_obligation(&group.key, 0, Some(&hash))
                    .is_err()
            );
            assert_eq!(fs::read_to_string(&path).unwrap(), original);
        }
    }
}
