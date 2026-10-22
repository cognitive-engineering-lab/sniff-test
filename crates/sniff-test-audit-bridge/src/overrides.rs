use super::*;
use sniff_test_report::OverrideAnnotation;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverrideDraft {
    pub annotation: OverrideAnnotation,
    pub location: Location,
    #[serde(default)]
    pub applied: bool,
    #[serde(default)]
    pub previous_document: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverrideApplyPlan {
    pub token: String,
    pub path: String,
    pub revision: u64,
    pub destinations: Vec<String>,
    pub destination: String,
    pub existing: bool,
    pub diff: String,
    #[serde(skip)]
    original: Option<String>,
    #[serde(skip)]
    content: String,
    #[serde(skip)]
    manifest: PathBuf,
    #[serde(skip)]
    manifest_original: Option<String>,
    #[serde(skip)]
    manifest_content: String,
}

impl Session {
    fn override_target(
        &mut self,
        id: &str,
        action: &str,
        revision: u64,
    ) -> Result<(AuditMetadata, EditTarget, Buffer)> {
        ensure!(
            !self.analysis.running && !self.analysis.stale,
            "reanalyze before editing overrides"
        );
        let audit = self
            .analysis
            .findings
            .iter()
            .find(|f| f.id == id)
            .and_then(|f| f.audit.clone())
            .context("finding no longer exists")?;
        let target = audit
            .targets
            .iter()
            .find(|t| t.action == action && t.selector.is_some())
            .cloned()
            .context("no verified override target")?;
        let buffer = self.buffer(&target.location.path)?;
        ensure!(
            !buffer.writable && !buffer.conflict && buffer.revision == revision,
            "override draft revision conflict"
        );
        ensure!(
            content_hash(buffer.original.as_bytes()) == target.location.hash,
            "dependency source changed; reanalyze"
        );
        Ok((audit, target, buffer))
    }

    pub fn override_template(&mut self, id: &str, action: &str, revision: u64) -> Result<String> {
        let (audit, target, buffer) = self.override_target(id, action, revision)?;
        if let Some(draft) = buffer.annotations.iter().find(|a| {
            a.annotation
                .selector
                .same_target(target.selector.as_ref().unwrap())
                && a.annotation.action == action
                && a.annotation.effect == audit.effect
        }) {
            return Ok(draft.annotation.document.clone());
        }
        // Use the workspace template generator on a standalone attachment point.
        let source = "fn target() {}\n";
        let mut location = target.location;
        location.start = 0;
        let text = documentation_edit(source, &location, action, &audit, "")?;
        Ok(text
            .strip_suffix(source)
            .context("invalid documentation template")?
            .trim_end_matches('\n')
            .to_owned())
    }

    pub fn save_override(
        &mut self,
        id: &str,
        action: &str,
        revision: u64,
        document: String,
    ) -> Result<Buffer> {
        let (audit, target, mut buffer) = self.override_target(id, action, revision)?;
        let marker = if action == "justification" {
            format!("// {}:", audit.justification.trim_end_matches(':'))
        } else {
            format!("/// # {}", audit.obligation.trim_start_matches('#').trim())
        };
        ensure!(
            document
                .lines()
                .next()
                .is_some_and(|l| l.trim_start().starts_with(&marker)),
            "keep the documentation template heading"
        );
        ensure!(
            document.lines().all(|l| l.trim().is_empty()
                || l.trim_start().starts_with(if action == "justification" {
                    "//"
                } else {
                    "///"
                })),
            "only documentation comments are allowed"
        );
        let body = document
            .trim_start()
            .strip_prefix(&marker)
            .unwrap_or_default();
        ensure!(
            body.lines()
                .any(|l| !l.trim().trim_start_matches('/').trim().is_empty()),
            "write an explanation first"
        );
        let annotation = OverrideAnnotation {
            effect: audit.effect,
            action: action.into(),
            document,
            selector: target.selector.unwrap(),
        };
        let previous_document = buffer
            .annotations
            .iter()
            .find(|a| {
                a.annotation.effect == annotation.effect
                    && a.annotation.action == annotation.action
                    && a.annotation.selector.same_target(&annotation.selector)
            })
            .and_then(|a| {
                a.previous_document
                    .clone()
                    .or_else(|| a.applied.then(|| a.annotation.document.clone()))
            });
        buffer.annotations.retain(|a| {
            !(a.annotation.effect == annotation.effect
                && a.annotation.action == annotation.action
                && a.annotation.selector.same_target(&annotation.selector))
        });
        buffer.annotations.push(OverrideDraft {
            annotation,
            location: target.location,
            applied: false,
            previous_document,
        });
        buffer.revision += 1;
        let previous = self.buffers.insert(buffer.path.clone(), buffer.clone());
        if let Err(error) = self.persist() {
            if let Some(previous) = previous {
                self.buffers.insert(buffer.path.clone(), previous);
            }
            return Err(error);
        }
        Ok(buffer)
    }

    /// Remove a new draft, or discard edits to an applied annotation.
    pub fn discard_override(&mut self, path: &str, revision: u64, index: usize) -> Result<Buffer> {
        ensure!(!self.analysis.running, "wait for analysis to finish");
        let mut buffer = self.buffer(path)?;
        ensure!(
            !buffer.writable && !buffer.conflict && buffer.revision == revision,
            "override draft revision conflict"
        );
        let draft = buffer
            .annotations
            .get_mut(index)
            .context("override draft no longer exists")?;
        ensure!(
            !draft.applied,
            "applied override documentation cannot be deleted"
        );
        ensure!(
            draft.location.hash == content_hash(buffer.original.as_bytes()),
            "dependency source changed; reanalyze"
        );
        if let Some(document) = draft.previous_document.clone() {
            draft.annotation.document = document;
            draft.applied = true;
        } else {
            buffer.annotations.remove(index);
        }
        buffer.revision += 1;
        let previous = self.buffers.insert(path.into(), buffer.clone());
        if let Err(error) = self.persist() {
            if let Some(previous) = previous {
                self.buffers.insert(path.into(), previous);
            }
            return Err(error);
        }
        self.pending_override = None;
        Ok(buffer)
    }

    pub fn edit_override(
        &mut self,
        path: &str,
        revision: u64,
        index: usize,
        document: String,
    ) -> Result<Buffer> {
        ensure!(!self.analysis.running, "wait for analysis to finish");
        let mut buffer = self.buffer(path)?;
        ensure!(
            !buffer.writable && !buffer.conflict && buffer.revision == revision,
            "override draft revision conflict"
        );
        let draft = buffer
            .annotations
            .get_mut(index)
            .context("override draft no longer exists")?;
        ensure!(
            draft.location.hash == content_hash(buffer.original.as_bytes()),
            "dependency source changed; reanalyze"
        );
        let heading = draft
            .annotation
            .document
            .lines()
            .next()
            .context("invalid stored documentation")?;
        let marker = if draft.annotation.action == "justification" {
            heading
                .split_once(':')
                .map(|(prefix, _)| format!("{prefix}:"))
                .context("invalid marker")?
        } else {
            heading.to_owned()
        };
        ensure!(
            document.trim_start().starts_with(&marker),
            "keep the documentation template heading"
        );
        ensure!(
            document.lines().all(|l| l.trim().is_empty()
                || l.trim_start()
                    .starts_with(if draft.annotation.action == "justification" {
                        "//"
                    } else {
                        "///"
                    })),
            "only documentation comments are allowed"
        );
        ensure!(
            document.trim_start()[marker.len()..].lines().any(|l| !l
                .trim()
                .trim_start_matches('/')
                .trim()
                .is_empty()),
            "write an explanation first"
        );
        if draft.applied {
            draft.previous_document = Some(draft.annotation.document.clone());
        }
        draft.annotation.document = document;
        draft.applied = false;
        buffer.revision += 1;
        let previous = self.buffers.insert(path.into(), buffer.clone());
        if let Err(error) = self.persist() {
            if let Some(previous) = previous {
                self.buffers.insert(path.into(), previous);
            }
            return Err(error);
        }
        Ok(buffer)
    }

    pub(super) fn override_preview(&self, buffer: &Buffer) -> Result<String> {
        self.annotation_preview(buffer, false)
    }
    pub(super) fn override_original_preview(&self, buffer: &Buffer) -> Result<String> {
        self.annotation_preview(buffer, true)
    }
    fn annotation_preview(&self, buffer: &Buffer, baseline: bool) -> Result<String> {
        if buffer.writable {
            return Ok(if baseline {
                buffer.original.clone()
            } else {
                buffer.content.clone()
            });
        }
        let mut content = buffer.original.clone();
        let mut drafts = buffer
            .annotations
            .iter()
            .filter(|a| !baseline || a.applied || a.previous_document.is_some())
            .collect::<Vec<_>>();
        drafts.sort_by_key(|a| {
            (
                std::cmp::Reverse(a.location.start),
                a.annotation.action.clone(),
                a.annotation.effect.clone(),
            )
        });
        for draft in drafts {
            ensure!(
                draft.location.hash == content_hash(buffer.original.as_bytes()),
                "dependency changed; cannot render override preview"
            );
            let at = draft.location.start;
            ensure!(
                at <= buffer.original.len() && buffer.original.is_char_boundary(at),
                "invalid override location"
            );
            let start = buffer.original[..at].rfind('\n').map_or(0, |i| i + 1);
            let indent = buffer.original[start..at]
                .chars()
                .take_while(|c| c.is_whitespace())
                .collect::<String>();
            let newline = if buffer.original.contains("\r\n") {
                "\r\n"
            } else {
                "\n"
            };
            let document = if baseline && !draft.applied {
                draft.previous_document.as_deref().unwrap_or_default()
            } else {
                &draft.annotation.document
            };
            let doc = document
                .lines()
                .map(|l| format!("{indent}{}{newline}", l.trim_start()))
                .collect::<String>();
            let start = outer_attribute_start(&buffer.original, start);
            content.insert_str(start, &doc);
        }
        Ok(content)
    }

    fn override_manifest(&self) -> PathBuf {
        let args = &self.config.arguments;
        let path = args
            .iter()
            .take_while(|a| a.as_str() != "--")
            .enumerate()
            .find_map(|(i, a)| {
                a.strip_prefix("--manifest=")
                    .map(PathBuf::from)
                    .or_else(|| {
                        (a == "--manifest")
                            .then(|| args.get(i + 1).map(PathBuf::from))
                            .flatten()
                    })
            })
            .unwrap_or_else(|| PathBuf::from("sniff-test.toml"));
        if path.is_absolute() {
            path
        } else {
            self.config.directory.join(path)
        }
    }

    fn checked_override_destination(&self, path: &Path) -> Result<PathBuf> {
        let parent = path
            .parent()
            .context("missing override directory")?
            .canonicalize()?;
        let path = parent.join(path.file_name().context("missing override filename")?);
        ensure!(
            parent.starts_with(&self.root),
            "override destination is outside this workspace"
        );
        if path.exists() {
            ensure!(
                path.canonicalize()?.starts_with(&self.root) && path.is_file(),
                "invalid override destination"
            );
        }
        Ok(path)
    }

    pub fn prepare_override_apply(
        &mut self,
        path: &str,
        revision: u64,
        destination: Option<&str>,
    ) -> Result<OverrideApplyPlan> {
        ensure!(!self.analysis.running, "wait for analysis to finish");
        let buffer = self.buffer(path)?;
        ensure!(
            !buffer.writable && !buffer.conflict && buffer.revision == revision,
            "override draft revision conflict"
        );
        ensure!(
            buffer.annotations.iter().any(|a| !a.applied),
            "no override drafts"
        );
        self.override_preview(&buffer)?;
        let manifest = self.checked_override_destination(&self.override_manifest())?;
        let manifest_original = read_optional(&manifest)?;
        let mut config = manifest_original
            .as_deref()
            .unwrap_or("")
            .parse::<toml_edit::Document>()?;
        let base = manifest.parent().unwrap();
        let configured = config
            .get("contracts")
            .and_then(|t| t.get("override-files"))
            .and_then(toml_edit::Item::as_array);
        let mut destinations = Vec::new();
        if let Some(paths) = configured {
            for value in paths {
                let path = PathBuf::from(value.as_str().context("invalid override-files entry")?);
                destinations.push(if path.is_absolute() {
                    path
                } else {
                    base.join(path)
                });
            }
        }
        if destinations.is_empty() {
            destinations.push(base.join("sniff-test-overrides.toml"));
        }
        let destinations = destinations
            .iter()
            .map(|p| {
                self.checked_override_destination(p)
                    .map(|p| p.to_string_lossy().into_owned())
            })
            .collect::<Result<Vec<_>>>()?;
        let destination = destination.unwrap_or(&destinations[0]).to_owned();
        ensure!(
            destinations.contains(&destination),
            "select a configured override destination"
        );
        ensure!(
            Path::new(&destination) != manifest,
            "override file cannot be the configuration file"
        );
        let original = read_optional(Path::new(&destination))?;
        let mut document = original
            .as_deref()
            .unwrap_or("")
            .parse::<toml_edit::Document>()?;
        // Validate known schema before touching an existing file.
        validate_override_file(original.as_deref().unwrap_or(""))?;
        if document.get("annotations").is_none() {
            document["annotations"] =
                toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new());
        }
        let entries = document["annotations"]
            .as_array_of_tables_mut()
            .context("annotations must be an array of tables")?;
        for draft in buffer.annotations.iter().filter(|a| !a.applied) {
            let annotation = &draft.annotation;
            let encoded = toml::to_string(annotation)?.parse::<toml_edit::Document>()?;
            let mut replacement = None;
            for (index, entry) in entries.iter().enumerate() {
                let mut existing = toml_edit::Document::new();
                *existing.as_table_mut() = entry.clone();
                let parsed: OverrideAnnotation = toml::from_str(&existing.to_string())?;
                if parsed.effect == annotation.effect
                    && parsed.action == annotation.action
                    && parsed.selector.same_target(&annotation.selector)
                {
                    replacement = Some(index);
                    break;
                }
            }
            let mut table = toml_edit::Table::new();
            for (key, item) in encoded.iter() {
                table[key] = if let Some(nested) = item.as_table() {
                    toml_edit::Item::Value(toml_edit::Value::InlineTable(
                        nested.clone().into_inline_table(),
                    ))
                } else {
                    item.clone()
                };
            }
            if let Some(index) = replacement {
                *entries.get_mut(index).unwrap() = table;
            } else {
                entries.push(table);
            }
        }
        let content = document.to_string();
        validate_override_file(&content)?;
        let relative = Path::new(&destination)
            .strip_prefix(base)
            .unwrap_or(Path::new(&destination))
            .to_string_lossy();
        if config.get("contracts").is_none() {
            config["contracts"] = toml_edit::Item::Table(toml_edit::Table::new());
        }
        if config["contracts"].get("override-files").is_none() {
            config["contracts"]["override-files"] = toml_edit::value(toml_edit::Array::new());
        }
        let paths = config["contracts"]["override-files"]
            .as_array_mut()
            .context("override-files must be an array")?;
        if !paths
            .iter()
            .filter_map(toml_edit::Value::as_str)
            .any(|p| base.join(p) == Path::new(&destination))
        {
            paths.push(relative.as_ref());
        }
        let manifest_content = config.to_string();
        let mut diff = unified(original.as_deref().unwrap_or(""), &content, &destination);
        if manifest_original.as_deref().unwrap_or("") != manifest_content {
            diff.push_str(&unified(
                manifest_original.as_deref().unwrap_or(""),
                &manifest_content,
                &manifest.to_string_lossy(),
            ));
        }
        let token = content_hash(format!("{path}:{revision}:{destination}:{original:?}:{manifest_original:?}:{content}:{manifest_content}").as_bytes());
        let plan = OverrideApplyPlan {
            token,
            path: path.into(),
            revision,
            destinations,
            destination,
            existing: original.is_some(),
            diff,
            original,
            content,
            manifest,
            manifest_original,
            manifest_content,
        };
        self.pending_override = Some(plan.clone());
        Ok(plan)
    }

    pub fn apply_overrides(&mut self, token: &str, confirmed: bool) -> Result<()> {
        ensure!(!self.analysis.running, "wait for analysis to finish");
        let plan = self
            .pending_override
            .clone()
            .context("review overrides before applying")?;
        ensure!(plan.token == token, "override preview expired");
        ensure!(
            !plan.existing || confirmed,
            "confirm editing the existing override file"
        );
        let buffer = self.buffer(&plan.path)?;
        ensure!(
            buffer.revision == plan.revision && !buffer.conflict,
            "override draft changed; review again"
        );
        self.checked_override_destination(Path::new(&plan.destination))?;
        self.checked_override_destination(&plan.manifest)?;
        ensure!(
            read_optional(Path::new(&plan.destination))? == plan.original
                && read_optional(&plan.manifest)? == plan.manifest_original,
            "override file or configuration changed; review again"
        );
        atomic_write(Path::new(&plan.destination), plan.content.as_bytes())?;
        if plan.manifest_original.as_deref().unwrap_or("") != plan.manifest_content {
            if let Err(error) = atomic_write(&plan.manifest, plan.manifest_content.as_bytes()) {
                if let Some(original) = &plan.original {
                    atomic_write(Path::new(&plan.destination), original.as_bytes())?;
                } else {
                    fs::remove_file(&plan.destination)?;
                }
                return Err(error);
            }
        }
        let saved = self.buffers.get_mut(&plan.path).unwrap();
        for draft in &mut saved.annotations {
            draft.applied = true;
            draft.previous_document = Some(draft.annotation.document.clone());
        }
        saved.revision += 1;
        self.analysis.stale = true;
        if let Err(error) = self.persist() {
            self.buffers.insert(plan.path.clone(), buffer);
            return Err(error);
        }
        self.pending_override = None;
        Ok(())
    }
}
fn read_optional(path: &Path) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}
fn unified(original: &str, content: &str, path: &str) -> String {
    similar::TextDiff::from_lines(original, content)
        .unified_diff()
        .header(path, path)
        .to_string()
}
fn validate_override_file(source: &str) -> Result<()> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct File {
        #[serde(default)]
        overrides: BTreeMap<String, String>,
        #[serde(default)]
        annotations: Vec<OverrideAnnotation>,
    }
    let file: File = toml::from_str(source)?;
    let _ = (file.overrides, file.annotations);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn setup() -> (tempfile::TempDir, tempfile::TempDir, Session, String) {
        let root = tempfile::tempdir().unwrap();
        let dep = tempfile::tempdir().unwrap();
        let path = dep.path().join("lib.rs");
        let source = "// λ\r\n#[inline]\r\npub fn sample() {\r\n    #[allow(\r\n        unused\r\n    )]\r\n    dangerous();\r\n}\r\n";
        fs::write(&path, source).unwrap();
        let mut session = Session::open(
            root.path().into(),
            root.path().join("target"),
            AnalysisConfig {
                executable: "false".into(),
                directory: root.path().into(),
                arguments: vec![],
            },
        )
        .unwrap();
        session
            .allowed_external
            .insert(path.canonicalize().unwrap());
        let buffer = session.buffer(path.to_str().unwrap()).unwrap();
        let location = Location {
            path: buffer.path.clone(),
            start: source.find("dangerous").unwrap(),
            end: source.find("dangerous").unwrap() + 11,
            source_id: "source".into(),
            hash: content_hash(source.as_bytes()),
            available: true,
        };
        let selector = sniff_test_report::OverrideSelector {
            definition: "definition".into(),
            namespace: "dep::sample".into(),
            source_id: "source".into(),
            source_hash: "hash".into(),
            package: "dep@0.1.0".into(),
            source_path: "src/lib.rs".into(),
            start: 27,
            end: 38,
            kind: "call".into(),
            site: Some("site".into()),
        };
        let facts = SemanticFacts {
            effect: "safety".into(),
            obligation: Some("Safety".into()),
            justification: Some("SAFETY".into()),
            source: Some(location.clone()),
            root: None,
            enclosing_function: None,
            justification_site: None,
            contract: None,
            trace: vec![],
            override_targets: vec![sniff_test_report::OverrideTarget {
                action: "justification".into(),
                location: location.clone(),
                selector,
            }],
        };
        let audit = adapt_semantics(
            facts,
            &serde_json::json!({"finding":"concrete-invocation","owner":{"scope":"dependency"}}),
        );
        session.analysis.stale = false;
        session.analysis.findings = vec![Finding {
            id: "finding".into(),
            crate_name: "app".into(),
            effect: Some("safety".into()),
            kind: "effect".into(),
            class: Some("concrete-invocation".into()),
            level: "warn".into(),
            root: None,
            trace_id: None,
            reason: "test".into(),
            requirements: vec![],
            missing_requirements: vec![],
            display_trace: vec![],
            audit: Some(audit),
            dependency: true,
        }];
        (root, dep, session, buffer.path)
    }
    #[test]
    fn override_drafts_restart_edit_discard_and_preserve_dependency_bytes() {
        let (root, _dep, mut session, path) = setup();
        let original = fs::read(&path).unwrap();
        assert!(
            session
                .save_override("finding", "justification", 0, "// SAFETY: ".into())
                .is_err()
        );
        let draft = session
            .save_override(
                "finding",
                "justification",
                0,
                "// SAFETY: pointer is valid".into(),
            )
            .unwrap();
        assert_eq!(draft.content.as_bytes(), original);
        assert!(
            session
                .diff(&path)
                .unwrap()
                .contains("+    // SAFETY: pointer is valid")
        );
        let preview = session.override_preview(&draft).unwrap();
        assert!(preview.contains("// SAFETY: pointer is valid\r\n    #[allow("));
        let config = session.config.clone();
        drop(session);
        let mut session =
            Session::open(root.path().into(), root.path().join("target"), config).unwrap();
        session.allowed_external.insert(PathBuf::from(&path));
        assert_eq!(session.drafts().len(), 1);
        assert!(
            session
                .edit_override(&path, 0, 0, "// SAFETY: changed".into())
                .is_err()
        );
        let updated = session
            .edit_override(
                &path,
                draft.revision,
                0,
                "// SAFETY: checked the pointer".into(),
            )
            .unwrap();
        assert_eq!(updated.annotations.len(), 1);
        assert!(session.discard_override(&path, 0, 0).is_err());
        session
            .discard_override(&path, updated.revision, 0)
            .unwrap();
        assert!(session.drafts().is_empty());
        assert!(session.diff(&path).unwrap().is_empty());
        let config = session.config.clone();
        drop(session);
        let mut session =
            Session::open(root.path().into(), root.path().join("target"), config).unwrap();
        assert!(session.drafts().is_empty());
        assert_eq!(fs::read(path).unwrap(), original);
    }
    #[test]
    fn existing_override_confirmation_and_concurrent_edits_are_enforced() {
        let (root, _dep, mut session, path) = setup();
        fs::write(
            root.path().join("sniff-test.toml"),
            "# config\n[contracts]\noverride-files=[\"one.toml\",\"two.toml\"]\n",
        )
        .unwrap();
        let original = "# preserve\n[overrides]\n\"other::api\" = \"# Safety\\nOld contract\"\n";
        for file in ["one.toml", "two.toml"] {
            fs::write(root.path().join(file), original).unwrap();
        }
        let draft = session
            .save_override(
                "finding",
                "justification",
                0,
                "// SAFETY: the pointer is valid".into(),
            )
            .unwrap();
        let plan = session
            .prepare_override_apply(&path, draft.revision, None)
            .unwrap();
        assert_eq!(plan.destinations.len(), 2);
        assert!(session.apply_overrides(&plan.token, false).is_err());
        fs::write(&plan.destination, format!("{original}# external edit\n")).unwrap();
        assert!(session.apply_overrides(&plan.token, true).is_err());
        assert_eq!(session.drafts().len(), 1);
        let plan = session
            .prepare_override_apply(&path, draft.revision, Some(&plan.destinations[1]))
            .unwrap();
        session.apply_overrides(&plan.token, true).unwrap();
        let applied = fs::read_to_string(&plan.destination).unwrap();
        assert!(applied.contains("# preserve"));
        assert!(applied.contains("other::api"));
        assert!(applied.contains("the pointer is valid"));
        assert!(session.drafts().is_empty());
        assert!(session.buffer(&path).unwrap().annotations[0].applied);
    }
    #[test]
    fn editing_then_discarding_an_applied_override_restores_its_document() {
        let (_root, _dep, mut session, path) = setup();
        let draft = session
            .save_override(
                "finding",
                "justification",
                0,
                "// SAFETY: original reason".into(),
            )
            .unwrap();
        let plan = session
            .prepare_override_apply(&path, draft.revision, None)
            .unwrap();
        session.apply_overrides(&plan.token, false).unwrap();
        let buffer = session.buffer(&path).unwrap();
        let edited = session
            .edit_override(
                &path,
                buffer.revision,
                0,
                "// SAFETY: revised reason".into(),
            )
            .unwrap();
        let diff = session.diff(&path).unwrap();
        assert!(diff.contains("-    // SAFETY: original reason"));
        assert!(diff.contains("+    // SAFETY: revised reason"));
        session.discard_override(&path, edited.revision, 0).unwrap();
        let restored = session.buffer(&path).unwrap();
        assert_eq!(
            restored.annotations[0].annotation.document,
            "// SAFETY: original reason"
        );
        assert!(restored.annotations[0].applied);
        assert!(
            session
                .discard_override(&path, restored.revision, 0)
                .is_err()
        );
        assert!(session.diff(&path).unwrap().is_empty());
    }
    #[test]
    fn vendored_dependency_sources_are_read_only_inside_workspace() {
        let (root, _dep, mut session, _) = setup();
        let source = root.path().join("vendor.rs");
        fs::write(&source, "fn dependency() {}\n").unwrap();
        let canonical = source.canonicalize().unwrap();
        session.dependency_sources.insert(canonical);
        let buffer = session.buffer(source.to_str().unwrap()).unwrap();
        assert!(!buffer.writable);
        assert!(
            session
                .update(&buffer.path, buffer.revision, "changed".into())
                .is_err()
        );
        assert!(session.apply(&buffer.path, buffer.revision).is_err());
        assert_eq!(fs::read_to_string(source).unwrap(), "fn dependency() {}\n");
    }
    #[test]
    fn source_conflicts_and_invalid_destinations_preserve_drafts() {
        let (root, _dep, mut session, path) = setup();
        let draft = session
            .save_override(
                "finding",
                "justification",
                0,
                "// SAFETY: pointer is valid".into(),
            )
            .unwrap();
        assert!(
            session
                .prepare_override_apply(&path, draft.revision, Some("/outside.toml"))
                .is_err()
        );
        fs::write(&path, "changed dependency").unwrap();
        assert!(
            session
                .prepare_override_apply(&path, draft.revision, None)
                .is_err()
        );
        assert!(session.drafts()[0].conflict);
        assert!(!root.path().join("sniff-test-overrides.toml").exists());
    }
}
