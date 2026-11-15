//! Trust boundaries selected by effect-origin crate ownership.
use super::namespace_trust::{edit_namespace, namespace_matches, namespace_patterns, read_config};
use super::*;

pub fn source_crate(finding: &Finding) -> Option<&str> {
    finding
        .direct_source
        .as_ref()?
        .owner
        .as_ref()?
        .1
        .as_deref()
        .filter(|name| !name.is_empty())
}

#[derive(Debug, Clone, Serialize)]
pub struct CrateEffectTrust {
    pub effect: String,
    pub count: usize,
    pub trusted: bool,
    pub exact: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CrateTrustDetail {
    pub crate_name: String,
    pub namespace: String,
    pub effects: Vec<CrateEffectTrust>,
    pub config_path: String,
    pub config_hash: Option<String>,
    pub results_revision: u64,
}

impl Session {
    pub fn crate_trust_detail(&self, name: &str) -> Result<CrateTrustDetail> {
        let mut counts = BTreeMap::<&str, usize>::new();
        for finding in &self.analysis.findings {
            if source_crate(finding) == Some(name)
                && let Some(effect) = finding.effect.as_deref()
            {
                *counts.entry(effect).or_default() += 1;
            }
        }
        ensure!(!counts.is_empty(), "crate no longer exists; reanalyze");
        let manifest = self.checked_override_destination(&self.override_manifest())?;
        let original = read_config(&manifest)?;
        let config = original
            .as_deref()
            .unwrap_or("")
            .parse::<toml_edit::Document>()?;
        let namespace = format!("{}::**", globset::escape(name));
        let mut effects = Vec::new();
        for (effect, count) in counts {
            let defaults = self
                .default_boundary_namespaces
                .get(effect)
                .map(Vec::as_slice)
                .unwrap_or_default();
            let patterns =
                namespace_patterns(&config, effect, "trusted-boundary-namespaces", defaults)?;
            namespace_matches(&patterns, "")?;
            let mut trusted = false;
            for pattern in &patterns {
                if pattern == "**"
                    || (pattern.ends_with("::**")
                        && namespace_matches(std::slice::from_ref(pattern), name)?)
                {
                    trusted = true;
                }
            }
            // Only an explicit entry may be removed; defaults and broader patterns are retained.
            let exact = config
                .get(effect)
                .and_then(|t| t.get("trusted-boundary-namespaces"))
                .and_then(toml_edit::Item::as_array)
                .is_some_and(|a| a.iter().any(|p| p.as_str() == Some(&namespace)));
            effects.push(CrateEffectTrust {
                effect: effect.into(),
                count,
                trusted,
                exact,
            });
        }
        Ok(CrateTrustDetail {
            crate_name: name.into(),
            namespace,
            effects,
            config_path: manifest.to_string_lossy().into_owned(),
            config_hash: original.as_ref().map(|s| content_hash(s.as_bytes())),
            results_revision: self.analysis.results_revision,
        })
    }

    pub fn set_crate_trust(
        &mut self,
        name: &str,
        effects: &[String],
        results_revision: u64,
        expected_hash: Option<&str>,
        trusted: bool,
    ) -> Result<CrateTrustDetail> {
        ensure!(!self.analysis.running, "analysis is running");
        ensure!(
            results_revision == self.analysis.results_revision,
            "crate selection is outdated; select it again"
        );
        let detail = self.crate_trust_detail(name)?;
        ensure!(!effects.is_empty(), "select at least one effect");
        for effect in effects {
            ensure!(
                detail.effects.iter().any(|e| &e.effect == effect),
                "effect is unavailable for this crate"
            );
        }
        if trusted
            && effects.iter().all(|effect| {
                detail
                    .effects
                    .iter()
                    .any(|e| &e.effect == effect && e.trusted)
            })
        {
            return Ok(detail);
        }
        ensure!(
            detail.config_hash.as_deref() == expected_hash,
            "configuration changed; select the crate again"
        );
        let manifest = Path::new(&detail.config_path);
        let original = read_config(manifest)?;
        ensure!(
            original
                .as_ref()
                .map(|s| content_hash(s.as_bytes()))
                .as_deref()
                == expected_hash,
            "configuration changed; select the crate again"
        );
        let mut config = original
            .as_deref()
            .unwrap_or("")
            .parse::<toml_edit::Document>()?;
        let selected: BTreeSet<_> = effects.iter().collect();
        for effect in selected {
            if trusted
                && detail
                    .effects
                    .iter()
                    .any(|e| &e.effect == effect && e.trusted)
            {
                continue;
            }
            if !trusted {
                ensure!(
                    detail
                        .effects
                        .iter()
                        .any(|e| &e.effect == effect && e.exact),
                    "no exact trust entry exists for this effect"
                );
            }
            let defaults = self
                .default_boundary_namespaces
                .get(effect)
                .map(Vec::as_slice)
                .unwrap_or_default();
            edit_namespace(
                &mut config,
                effect,
                "trusted-boundary-namespaces",
                defaults,
                &detail.namespace,
                trusted,
            )?;
        }
        self.save_trust_config(manifest, original, config)?;
        self.crate_trust_detail(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn report(id: &str, effect: &str, source: &str) -> Finding {
        serde_json::from_value(json!({
            "id":id,"crate_name":"reporting_app","effect":effect,"kind":"effect","class":"concrete-operation","level":"warn","root":"reporting_app::root","reason":"test",
            "requirements":[],"missing_requirements":[],"display_trace":[],
            "direct_source":{"source":[source,source,0,1],"kind":[effect,0,null],"function":"dep::work","target":null,"owner":[1,"dep"],"missing_requirements":[],"requirements":[]}
        })).unwrap()
    }

    #[test]
    fn multi_effect_trust_preserves_defaults_comments_and_other_settings() {
        let dir = tempfile::tempdir().unwrap();
        let mut session = super::super::tests::session(dir.path());
        session.analysis.findings = vec![
            report("a", "panic", "dep-1.rs"),
            report("b", "panic", "dep-2.rs"),
            report("c", "custom", "dep.rs"),
        ];
        session.set_default_boundary_namespaces(BTreeMap::from([(
            "panic".into(),
            vec!["default::boundary".into()],
        )]));
        let path = dir.path().join("sniff-test.toml");
        fs::write(&path, "# preserve\n[panic]\nignored-namespaces = [\"keep\"] # retained\n[custom]\ntrusted-boundary-namespaces = []\n").unwrap();
        let detail = session.crate_trust_detail("dep").unwrap();
        assert_eq!(
            detail
                .effects
                .iter()
                .find(|e| e.effect == "panic")
                .unwrap()
                .count,
            2
        );
        assert!(session.crate_trust_detail("reporting_app").is_err());
        let effects = vec!["panic".into(), "custom".into()];
        let saved = session
            .set_crate_trust("dep", &effects, 0, detail.config_hash.as_deref(), true)
            .unwrap();
        assert!(saved.effects.iter().all(|e| e.trusted && e.exact));
        let text = fs::read_to_string(&path).unwrap();
        assert!(
            text.contains("# preserve")
                && text.contains("# retained")
                && text.contains("default::boundary")
        );
        let config: toml::Value = text.parse().unwrap();
        assert_eq!(
            config["panic"]["ignored-namespaces"][0].as_str(),
            Some("keep")
        );
        assert_eq!(
            config["panic"]["trusted-boundary-namespaces"][1].as_str(),
            Some("dep::**")
        );
        session
            .set_crate_trust("dep", &effects, 0, detail.config_hash.as_deref(), true)
            .unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), text);
        assert!(session.analysis.stale && session.analysis.overrides_changed);
        let removed = session
            .set_crate_trust("dep", &effects, 0, saved.config_hash.as_deref(), false)
            .unwrap();
        assert!(removed.effects.iter().all(|e| !e.trusted && !e.exact));
        assert!(
            fs::read_to_string(&path)
                .unwrap()
                .contains("default::boundary")
        );
    }

    #[test]
    fn stale_invalid_and_partial_requests_never_write() {
        let dir = tempfile::tempdir().unwrap();
        let mut session = super::super::tests::session(dir.path());
        session.analysis.findings = vec![
            report("a", "panic", "dep.rs"),
            report("b", "custom", "dep.rs"),
        ];
        let detail = session.crate_trust_detail("dep").unwrap();
        let selected = vec!["panic".into()];
        assert!(
            session
                .set_crate_trust("dep", &selected, 1, None, true)
                .is_err()
        );
        session.analysis.running = true;
        assert!(
            session
                .set_crate_trust("dep", &selected, 0, None, true)
                .is_err()
        );
        session.analysis.running = false;
        assert!(session.set_crate_trust("dep", &[], 0, None, true).is_err());
        assert!(
            session
                .set_crate_trust("dep", &["missing".into()], 0, None, true)
                .is_err()
        );
        let path = dir.path().join("sniff-test.toml");
        assert!(!path.exists());
        fs::write(&path, "# changed\n").unwrap();
        assert!(
            session
                .set_crate_trust("dep", &selected, 0, detail.config_hash.as_deref(), true)
                .is_err()
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), "# changed\n");
        for invalid in [
            "custom=3\n",
            "[custom]\ntrusted-boundary-namespaces=[3]\n",
            "[custom]\ntrusted-boundary-namespaces=[\"[\"]\n",
        ] {
            fs::write(&path, invalid).unwrap();
            assert!(
                session
                    .set_crate_trust(
                        "dep",
                        &["panic".into(), "custom".into()],
                        0,
                        Some(&content_hash(invalid.as_bytes())),
                        true
                    )
                    .is_err()
            );
            assert_eq!(fs::read_to_string(&path).unwrap(), invalid);
        }
    }

    #[test]
    fn broader_coverage_remains_after_exact_removal() {
        let dir = tempfile::tempdir().unwrap();
        let mut session = super::super::tests::session(dir.path());
        session.analysis.findings = vec![report("a", "panic", "dep.rs")];
        let path = dir.path().join("sniff-test.toml");
        fs::write(
            &path,
            "[panic]\ntrusted-boundary-namespaces=[\"**\", \"dep::**\"]\n",
        )
        .unwrap();
        let detail = session.crate_trust_detail("dep").unwrap();
        let removed = session
            .set_crate_trust(
                "dep",
                &["panic".into()],
                0,
                detail.config_hash.as_deref(),
                false,
            )
            .unwrap();
        assert!(removed.effects[0].trusted && !removed.effects[0].exact);
        assert!(
            session
                .set_crate_trust(
                    "dep",
                    &["panic".into()],
                    0,
                    removed.config_hash.as_deref(),
                    false
                )
                .is_err()
        );
        let value: toml::Value = fs::read_to_string(path).unwrap().parse().unwrap();
        assert_eq!(
            value["panic"]["trusted-boundary-namespaces"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }
}
