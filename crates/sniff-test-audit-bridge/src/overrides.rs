use super::*;
/// Documentation and verified source-selector metadata retained by the audit session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverrideDocument {
    pub effect: String,
    pub action: String,
    pub document: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obligation_documentation: Option<sniff_test_report::ObligationDocumentation>,
    pub selector: sniff_test_report::OverrideSelector,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedOverride {
    pub annotation: OverrideDocument,
    pub location: Location,
    pub destination: String,
}
struct OverrideFileWrite {
    destination: String,
    original: Option<String>,
    content: String,
    manifest: PathBuf,
    manifest_original: Option<String>,
    manifest_content: String,
}

/// A verified attachment point for the direct-save editor.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OverrideEditorTarget {
    Finding {
        id: String,
        action: String,
        revision: u64,
        generation: u64,
    },
    Saved {
        path: String,
        index: usize,
        revision: u64,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct OverrideDestination {
    pub path: String,
    pub exists: bool,
}

/// File snapshots stay on the server and expire when another editor is opened.
#[derive(Debug, Clone, Serialize)]
pub struct OverrideEditor {
    pub token: String,
    pub document: String,
    pub obligation_documentation: Option<sniff_test_report::ObligationDocumentation>,
    pub destinations: Vec<OverrideDestination>,
    pub destination: String,
    #[serde(skip)]
    target: OverrideEditorTarget,
    #[serde(skip)]
    saved: SavedOverride,
    #[serde(skip)]
    index: Option<usize>,
    #[serde(skip)]
    generation: u64,
    #[serde(skip)]
    manifest_original: Option<String>,
    #[serde(skip)]
    originals: BTreeMap<String, Option<String>>,
}

impl Session {
    pub fn open_override_editor(&mut self, target: OverrideEditorTarget) -> Result<OverrideEditor> {
        ensure!(
            !self.analysis.running,
            "wait for analysis to finish before editing overrides"
        );
        let (saved, index) = match &target {
            OverrideEditorTarget::Finding {
                id,
                action,
                revision,
                generation,
            } => {
                ensure!(
                    *generation == self.analysis.generation,
                    "Analysis changed; reopen the override editor."
                );
                let (audit, attachment, buffer) = self.override_target(id, action, *revision)?;
                let selector = attachment.selector.as_ref().unwrap();
                if let Some(index) = buffer.saved_overrides.iter().position(|saved| {
                    saved.annotation.effect == audit.effect
                        && saved.annotation.action == *action
                        && saved.annotation.selector.same_target(selector)
                }) {
                    (buffer.saved_overrides[index].clone(), Some(index))
                } else {
                    let source = "fn target() {}\n";
                    let mut location = attachment.location.clone();
                    location.start = 0;
                    let template = documentation_edit(source, &location, action, &audit, "")?;
                    let document = template
                        .strip_suffix(source)
                        .context("invalid documentation template")?
                        .trim_end_matches('\n')
                        .to_owned();
                    (
                        SavedOverride {
                            annotation: OverrideDocument {
                                effect: audit.effect,
                                action: action.clone(),
                                document,
                                obligation_documentation: (action == "justification")
                                    .then_some(audit.obligation_documentation)
                                    .flatten(),
                                selector: attachment.selector.unwrap(),
                            },
                            location: attachment.location,
                            destination: String::new(),
                        },
                        None,
                    )
                }
            }
            OverrideEditorTarget::Saved {
                path,
                index,
                revision,
            } => {
                let buffer = self.buffer(path)?;
                ensure!(
                    !buffer.writable && buffer.revision == *revision,
                    "override revision conflict"
                );
                let saved = buffer
                    .saved_overrides
                    .get(*index)
                    .context("override no longer exists")?
                    .clone();
                ensure!(
                    saved.location.hash == content_hash(buffer.content.as_bytes()),
                    "dependency source changed; reanalyze"
                );
                (saved, Some(*index))
            }
        };
        let (_, manifest_original, paths) = self.override_destinations()?;
        let mut originals = BTreeMap::new();
        let mut destinations = Vec::new();
        let destination = if index.is_some() {
            ensure!(
                paths.contains(&saved.destination),
                "saved override destination is no longer configured"
            );
            saved.destination.clone()
        } else {
            paths[0].clone()
        };
        for path in paths {
            let original = read_optional(Path::new(&path))?;
            destinations.push(OverrideDestination {
                path: path.clone(),
                exists: original.is_some(),
            });
            originals.insert(path, original);
        }
        let token = content_hash(
            format!(
                "{target:?}:{}:{manifest_original:?}:{originals:?}",
                self.analysis.generation
            )
            .as_bytes(),
        );
        let editor = OverrideEditor {
            token,
            document: saved.annotation.document.clone(),
            obligation_documentation: saved.annotation.obligation_documentation.clone(),
            destinations,
            destination,
            target,
            saved,
            index,
            generation: self.analysis.generation,
            manifest_original,
            originals,
        };
        self.pending_editor = Some(editor.clone());
        Ok(editor)
    }

    /// Save just the edited annotation, without persisting a temporary draft or starting analysis.
    pub fn commit_override(
        &mut self,
        token: &str,
        destination: &str,
        filename: Option<&str>,
        document: String,
    ) -> Result<(Buffer, String)> {
        ensure!(
            !self.analysis.running,
            "wait for analysis to finish before editing overrides"
        );
        let editor = self
            .pending_editor
            .clone()
            .context("reopen the override editor before saving")?;
        ensure!(
            editor.token == token && editor.generation == self.analysis.generation,
            "Analysis or editor changed; reopen the override editor."
        );
        let (_, manifest_original, _) = self.override_destinations()?;
        ensure!(
            manifest_original == editor.manifest_original,
            "Configuration changed; reopen the override editor before saving."
        );
        for (path, original) in &editor.originals {
            ensure!(
                read_optional(Path::new(path))? == *original,
                "Override file changed; reopen the override editor before saving."
            );
        }
        let original = editor
            .originals
            .get(destination)
            .context("select a configured override destination")?;
        let selected_destination = destination;
        let create = original.is_none();
        let destination = if create {
            let filename = filename
                .context("provide a name for the override file")?
                .trim();
            ensure!(
                !filename.is_empty()
                    && Path::new(filename).file_name().and_then(|s| s.to_str()) == Some(filename)
                    && !filename.contains(['/', '\\']),
                "Enter a filename without directories."
            );
            let manifest = self.override_manifest();
            self.checked_override_destination(&manifest.parent().unwrap().join(filename))?
                .to_string_lossy()
                .into_owned()
        } else {
            ensure!(
                filename.is_none(),
                "an existing override does not need a new filename"
            );
            destination.to_owned()
        };
        let revision = match &editor.target {
            OverrideEditorTarget::Finding { revision, .. }
            | OverrideEditorTarget::Saved { revision, .. } => *revision,
        };
        let mut buffer = self.buffer(&editor.saved.location.path)?;
        ensure!(
            !buffer.writable && buffer.revision == revision,
            "override revision conflict"
        );
        ensure!(
            editor.saved.location.hash == content_hash(buffer.content.as_bytes()),
            "dependency source changed; reanalyze"
        );
        validate_override_document(&document, &editor.saved.annotation)?;
        let mut saved = editor.saved.clone();
        saved.annotation.document = document;
        saved.destination = destination.clone();
        for other in &buffer.saved_overrides {
            let left = &saved.annotation.selector;
            let right = &other.annotation.selector;
            if saved.annotation.action == "obligation"
                && saved.destination == other.destination
                && left.crate_name == right.crate_name
                && left.version == right.version
                && source_key(left) == source_key(right)
            {
                ensure!(
                    left.definition == right.definition,
                    "source selector matches multiple definitions"
                );
            }
        }
        let original_document = editor
            .index
            .filter(|_| !create)
            .map(|_| editor.saved.annotation.document.as_str());
        let mut plan = self.prepare_override_write(
            &saved.annotation,
            original_document,
            &destination,
            create,
        )?;
        if create && destination != selected_destination {
            let base = plan.manifest.parent().unwrap();
            let mut config = plan.manifest_content.parse::<toml_edit::Document>()?;
            if let Some(paths) = config["contracts"]["override-files"].as_array_mut() {
                paths.retain(|value| {
                    value
                        .as_str()
                        .is_none_or(|path| base.join(path) != Path::new(selected_destination))
                });
            }
            plan.manifest_content = config.to_string();
        }
        self.write_override_files(&plan)?;
        if let Some(index) = editor.index {
            buffer.saved_overrides[index] = saved;
        } else {
            buffer.saved_overrides.push(saved);
        }
        buffer.revision += 1;
        let previous = self.buffers.insert(buffer.path.clone(), buffer.clone());
        if let Err(error) = self.persist() {
            if let Some(previous) = previous {
                self.buffers.insert(buffer.path.clone(), previous);
            }
            restore_optional(Path::new(&plan.destination), &plan.original)?;
            restore_optional(&plan.manifest, &plan.manifest_original)?;
            return Err(error);
        }
        self.analysis.overrides_changed = true;
        self.pending_editor = None;
        Ok((buffer, destination))
    }

    fn override_target(
        &mut self,
        id: &str,
        action: &str,
        revision: u64,
    ) -> Result<(AuditMetadata, EditTarget, Buffer)> {
        ensure!(
            !self.analysis.running,
            "wait for analysis to finish before editing overrides"
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
        ensure!(
            target.location.available,
            "override attachment changed; reanalyze"
        );
        let buffer = self.buffer(&target.location.path)?;
        ensure!(
            !buffer.writable && buffer.revision == revision,
            "override revision conflict"
        );
        ensure!(
            content_hash(buffer.content.as_bytes()) == target.location.hash,
            "dependency source changed; reanalyze"
        );
        Ok((audit, target, buffer))
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

    fn override_destinations(&self) -> Result<(PathBuf, Option<String>, Vec<String>)> {
        let manifest = self.checked_override_destination(&self.override_manifest())?;
        let manifest_original = read_optional(&manifest)?;
        let config = manifest_original
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
        Ok((manifest, manifest_original, destinations))
    }

    fn prepare_override_write(
        &self,
        annotation: &OverrideDocument,
        original_document: Option<&str>,
        destination: &str,
        create: bool,
    ) -> Result<OverrideFileWrite> {
        let (manifest, manifest_original, destinations) = self.override_destinations()?;
        let base = manifest.parent().unwrap();
        let mut config = manifest_original
            .as_deref()
            .unwrap_or("")
            .parse::<toml_edit::Document>()?;
        let destination = destination.to_owned();
        ensure!(
            create || destinations.contains(&destination),
            "select a configured override destination"
        );
        ensure!(
            Path::new(&destination) != manifest,
            "override file cannot be the configuration file"
        );
        let destination = self
            .checked_override_destination(Path::new(&destination))?
            .to_string_lossy()
            .into_owned();
        let original = read_optional(Path::new(&destination))?;
        ensure!(
            !create || original.is_none(),
            "That override file already exists. Choose another name."
        );
        let mut document = original
            .as_deref()
            .unwrap_or("")
            .parse::<toml_edit::Document>()?;
        // Validate known schema before touching an existing file.
        validate_override_file(original.as_deref().unwrap_or(""))?;
        for other in destinations.iter().filter(|p| **p != destination) {
            let text = read_optional(Path::new(other))?.unwrap_or_default();
            validate_override_file(&text)?;
            let parsed: OverrideFile = toml::from_str(&text)?;
            let selector = &annotation.selector;
            if let Some(entries) = parsed
                .overrides
                .crates
                .get(&selector.crate_name)
                .and_then(|v| v.get(&selector.version))
            {
                for key in entries.keys() {
                    let (path, start, end) = parse_lines(key)?;
                    ensure!(
                        path != selector.source_path
                            || selector.line < start
                            || selector.line > end,
                        "overlapping source override in {other}: {key}"
                    );
                }
            }
        }
        merge_source_override(&mut document, annotation, original_document)?;
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
        Ok(OverrideFileWrite {
            destination,
            original,
            content,
            manifest,
            manifest_original,
            manifest_content,
        })
    }

    fn write_override_files(&self, plan: &OverrideFileWrite) -> Result<()> {
        self.checked_override_destination(Path::new(&plan.destination))?;
        self.checked_override_destination(&plan.manifest)?;
        ensure!(
            read_optional(Path::new(&plan.destination))? == plan.original
                && read_optional(&plan.manifest)? == plan.manifest_original,
            "override file or configuration changed; review again"
        );
        if plan.original.is_none() {
            let mut file =
                tempfile::NamedTempFile::new_in(Path::new(&plan.destination).parent().unwrap())?;
            file.write_all(plan.content.as_bytes())?;
            file.as_file().sync_all()?;
            file.persist_noclobber(&plan.destination)
                .map_err(|e| e.error)?;
        } else {
            atomic_write(Path::new(&plan.destination), plan.content.as_bytes())?;
        }
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
        Ok(())
    }
}
fn restore_optional(path: &Path, original: &Option<String>) -> Result<()> {
    if let Some(original) = original {
        atomic_write(path, original.as_bytes())?;
    } else if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}
fn read_optional(path: &Path) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}
use sniff_test_report::source_overrides::{OverrideFile, SourceContractSelector};

fn source_key(selector: &sniff_test_report::OverrideSelector) -> String {
    format!(
        "{}:{}:{}",
        selector.source_path, selector.line, selector.line
    )
}
fn parse_lines(key: &str) -> Result<(&str, u32, u32)> {
    let selector = SourceContractSelector::parse("validation", "0.0.0", key)?;
    let (path, _) = key.rsplit_once(':').unwrap().0.rsplit_once(':').unwrap();
    Ok((path, selector.start_line(), selector.end_line()))
}

fn validate_override_file(source: &str) -> Result<()> {
    let file: OverrideFile = toml::from_str(source)?;
    for (name, versions) in file.overrides.crates {
        SourceContractSelector::validate_crate_name(&name)?;
        for (version, entries) in versions {
            SourceContractSelector::validate_version(&version)?;
            for key in entries.keys() {
                parse_lines(key)?;
            }
        }
    }
    for pattern in file.overrides.namespaces.keys() {
        globset::Glob::new(pattern)?;
    }
    Ok(())
}

fn markdown(document: &str, action: &str) -> String {
    let prefix = if action == "justification" {
        "//"
    } else {
        "///"
    };
    document
        .lines()
        .map(|line| {
            let line = line.trim_start().strip_prefix(prefix).unwrap_or(line);
            line.strip_prefix(' ').unwrap_or(line)
        })
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_owned()
}

// Replace just this contract section; keep prose and every other effect's contract.
fn replace_section(base: &str, replacement: &str) -> String {
    let heading = replacement.lines().next().unwrap_or_default().trim();
    let lines = base.lines().collect::<Vec<_>>();
    if let Some(start) = lines
        .iter()
        .position(|l| l.trim().eq_ignore_ascii_case(heading))
    {
        let level = heading.chars().take_while(|c| *c == '#').count();
        let end = (start + 1..lines.len())
            .find(|&i| {
                let l = lines[i].trim_start();
                let n = l.chars().take_while(|c| *c == '#').count();
                n > 0 && n <= level && l.as_bytes().get(n) == Some(&b' ')
            })
            .unwrap_or(lines.len());
        [
            lines[..start].join("\n"),
            replacement.to_owned(),
            lines[end..].join("\n"),
        ]
        .into_iter()
        .filter(|s| !s.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n\n")
    } else {
        [base.trim(), replacement.trim()]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("\n\n")
    }
}

fn validate_override_document(document: &str, annotation: &OverrideDocument) -> Result<()> {
    let heading = annotation
        .document
        .lines()
        .next()
        .context("invalid stored documentation")?;
    let marker = if annotation.action == "justification" {
        heading
            .split_once(':')
            .map(|(prefix, _)| format!("{prefix}:"))
            .context("invalid marker")?
    } else {
        heading.to_owned()
    };
    let body = document
        .trim_start()
        .strip_prefix(&marker)
        .context("keep the documentation template heading")?;
    ensure!(
        document.lines().all(|line| line.trim().is_empty()
            || line
                .trim_start()
                .starts_with(if annotation.action == "justification" {
                    "//"
                } else {
                    "///"
                })),
        "only documentation comments are allowed"
    );
    ensure!(
        body.lines()
            .any(|line| !line.trim().trim_start_matches('/').trim().is_empty()),
        "write an explanation first"
    );
    Ok(())
}

fn merge_source_override(
    document: &mut toml_edit::Document,
    annotation: &OverrideDocument,
    original_document: Option<&str>,
) -> Result<()> {
    let selector = &annotation.selector;
    let name = &selector.crate_name;
    let version = &selector.version;
    let key = source_key(selector);
    let action = &annotation.action;
    let (path, start, end) = parse_lines(&key)?;
    let parsed: OverrideFile = toml::from_str(&document.to_string())?;
    let entries = parsed
        .overrides
        .crates
        .get(name)
        .and_then(|v| v.get(version));
    if let Some(entries) = entries {
        for existing in entries.keys().filter(|existing| *existing != &key) {
            let (other_path, other_start, other_end) = parse_lines(existing)?;
            ensure!(
                path != other_path || start > other_end || other_start > end,
                "overlapping source overrides: {existing} and {key}"
            );
        }
    }
    let existing = entries
        .and_then(|entries| entries.get(&key))
        .map(String::as_str);
    let mut value = existing
        .unwrap_or(if action == "obligation" {
            &selector.documentation
        } else {
            ""
        })
        .to_owned();
    if let Some(existing) = existing {
        let is_marker = existing
            .lines()
            .find(|line| !line.trim().is_empty())
            .is_some_and(|line| {
                let line = line.trim().strip_prefix("//").unwrap_or(line).trim();
                selector.justification_headers.iter().any(|header| {
                    line.strip_prefix(header)
                        .is_some_and(|rest| rest.starts_with(':'))
                })
            });
        ensure!(
            is_marker == (action == "justification"),
            "obligation and justification source-selector collision at {key}"
        );
    }
    let new = markdown(&annotation.document, action);
    if action == "obligation" {
        value = replace_section(&value, &new);
    } else if let Some(original) = original_document {
        let original = markdown(original, action);
        ensure!(
            value.contains(&original),
            "saved override contribution changed at {key}"
        );
        value = value.replacen(&original, &new, 1);
    } else {
        if !value.trim().is_empty() {
            value.push_str("\n\n");
        }
        value.push_str(&new);
    }
    let mut table: &mut dyn toml_edit::TableLike = document.as_table_mut();
    for key in ["overrides", "crates", name, version] {
        let entry = table
            .entry(key)
            .or_insert(toml_edit::Item::Table(toml_edit::Table::new()));
        table = entry
            .as_table_like_mut()
            .context("override entries must be tables")?;
    }
    let item = &mut document["overrides"]["crates"][name][version][&key];
    let decor = item.as_value().map(|value| value.decor().clone());
    *item = toml_edit::value(value);
    if let Some(decor) = decor {
        *item.as_value_mut().unwrap().decor_mut() = decor;
    }
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
            crate_name: "dep".into(),
            version: "0.1.0".into(),
            line: 7,
            documentation: String::new(),
            justification_headers: vec!["SAFETY".into(), "PANIC".into(), "ALLOC".into()],
            source_path: "src/lib.rs".into(),
            start: 27,
            end: 38,
            kind: "call".into(),
            site: Some("site".into()),
        };
        let facts = SemanticFacts {
            direct_source: None,
            effect: "safety".into(),
            obligation: Some("Safety".into()),
            justification: Some("SAFETY".into()),
            source: Some(location.clone()),
            root: None,
            enclosing_function: None,
            justification_site: None,
            contract: None,
            obligation_documentation: None,
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
            direct_source: None,
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
    fn annotation() -> OverrideDocument {
        let (_root, _dep, mut session, path) = setup();
        let mut annotation = editor(&mut session, &path).saved.annotation;
        annotation.document = "// SAFETY: first".into();
        annotation
    }
    fn value(document: &toml_edit::Document, key: &str) -> String {
        let parsed: OverrideFile = toml::from_str(&document.to_string()).unwrap();
        parsed.overrides.crates["dep"]["0.1.0"][key].clone()
    }
    #[test]
    fn single_annotation_edits_preserve_same_line_contributions_and_comments() {
        let mut first = annotation();
        let mut second = first.clone();
        second.selector.site = Some("second site".into());
        second.document = "// SAFETY: second".into();
        let mut other = first.clone();
        other.effect = "panic".into();
        other.document = "// PANIC: checked".into();
        let mut document = "# file comment\n[overrides.crates.dep.\"0.1.0\"]\n# nearby comment\n\"src/lib.rs:20:20\" = \"# Safety\\nKeep this contract\" # inline\n".parse().unwrap();
        for annotation in [&first, &second, &other] {
            merge_source_override(&mut document, annotation, None).unwrap();
        }
        let text = value(&document, "src/lib.rs:7:7");
        assert_eq!(text.matches("SAFETY:").count(), 2);
        assert_eq!(text.matches("PANIC:").count(), 1);
        let original = first.document.clone();
        first.document = "// SAFETY: revised\n// continued".into();
        merge_source_override(&mut document, &first, Some(&original)).unwrap();
        let text = value(&document, "src/lib.rs:7:7");
        assert!(!text.contains("first"));
        assert!(text.contains("SAFETY: revised\ncontinued"));
        assert!(text.contains("SAFETY: second") && text.contains("PANIC: checked"));
        let saved = document.to_string();
        assert!(saved.contains("# nearby comment") && saved.contains("# inline"));
        validate_override_file(&saved).unwrap();
    }
    #[test]
    fn obligations_preserve_effective_rustdoc_and_other_contracts() {
        let mut annotation = annotation();
        annotation.action = "obligation".into();
        annotation.document = "/// # Panics\n/// Checked by caller.".into();
        annotation.selector.documentation = "Summary.\n\n# Safety\nPointer must be valid.\n\n# Panics\nOld.\n\n# Examples\nExample.".into();
        let mut document = toml_edit::Document::new();
        merge_source_override(&mut document, &annotation, None).unwrap();
        let text = value(&document, "src/lib.rs:7:7");
        assert!(
            text.contains("# Safety\nPointer must be valid.")
                && text.contains("# Examples\nExample.")
        );
        assert!(text.contains("# Panics\nChecked by caller.") && !text.contains("Old."));
        assert!(text.starts_with("Summary."));
        annotation.effect = "safety".into();
        annotation.document = "/// # Safety\n/// New safety contract.".into();
        merge_source_override(&mut document, &annotation, None).unwrap();
        let text = value(&document, "src/lib.rs:7:7");
        assert!(text.contains("# Panics\nChecked by caller."));
        assert_eq!(text.matches("# Safety").count(), 1);
    }
    #[test]
    fn writer_supports_inline_tables_and_preserves_entry_comments() {
        let annotation = annotation();
        let text = "# top\n[overrides.crates.dep]\n\"0.1.0\" = { \"src/lib.rs:7:7\" = \"SAFETY: existing\" } # keep\n";
        let mut document = text.parse().unwrap();
        merge_source_override(&mut document, &annotation, None).unwrap();
        assert!(document.to_string().contains("# keep"));
        assert_eq!(
            value(&document, "src/lib.rs:7:7"),
            "SAFETY: existing\n\nSAFETY: first"
        );
        validate_override_file(&document.to_string()).unwrap();
    }
    #[test]
    fn writer_rejects_collisions_ranges_and_unknown_schema_before_writing() {
        assert!(validate_override_file("[[annotations]]\neffect=\"panic\"\n").is_err());
        let mut annotation = annotation();
        for text in [
            "[overrides.crates.dep.\"0.1.0\"]\n\"src/lib.rs:6:8\"=\"SAFETY: existing\"",
            "[overrides.crates.dep.\"0.1.0\"]\n\"src/lib.rs:7:7\"=\"# Safety\\nExisting\"",
        ] {
            assert!(merge_source_override(&mut text.parse().unwrap(), &annotation, None).is_err());
        }
        let mut document = toml_edit::Document::new();
        merge_source_override(&mut document, &annotation, None).unwrap();
        annotation.action = "obligation".into();
        annotation.document = "/// # Safety\n/// Required.".into();
        assert!(merge_source_override(&mut document, &annotation, None).is_err());
    }

    #[test]
    fn saved_overrides_restart_and_edit_without_source_changes_or_draft_state() {
        let (root, _dep, mut session, path) = setup();
        let source = fs::read(&path).unwrap();
        let documentation = sniff_test_report::ObligationDocumentation {
            prototype: Some("unsafe fn contract(pointer: *const u8) -> u8".into()),
            function: "dep::contract".into(),
            markdown: "# Safety\nThe pointer must be valid.".into(),
        };
        session.analysis.findings[0]
            .audit
            .as_mut()
            .unwrap()
            .obligation_documentation = Some(documentation.clone());
        let context = editor(&mut session, &path);
        session
            .commit_override(
                &context.token,
                &context.destination,
                Some("saved.toml"),
                "// SAFETY: pointer is valid".into(),
            )
            .unwrap();
        let config = session.config.clone();
        let analysis = session.analysis.clone();
        let serialized = fs::read_to_string(&session.metadata_file).unwrap();
        assert!(serialized.contains("pointer is valid"));
        assert!(!serialized.contains("dangerous()"));
        for legacy in ["\"annotations\"", "previous_document", "applied"] {
            assert!(!serialized.contains(legacy));
        }
        drop(session);
        let mut session =
            Session::open(root.path().into(), root.path().join("target"), config).unwrap();
        session.analysis = analysis;
        let buffer = session.buffer(&path).unwrap();
        assert_eq!(buffer.saved_overrides.len(), 1);

        let context = session
            .open_override_editor(OverrideEditorTarget::Saved {
                path: path.clone(),
                revision: buffer.revision,
                index: 0,
            })
            .unwrap();
        assert_eq!(context.obligation_documentation, Some(documentation));
        assert_eq!(context.document, "// SAFETY: pointer is valid");
        session
            .commit_override(
                &context.token,
                &context.destination,
                None,
                "// SAFETY: pointer was checked".into(),
            )
            .unwrap();
        let saved = fs::read_to_string(context.destination).unwrap();
        assert!(saved.contains("pointer was checked") && !saved.contains("pointer is valid"));
        assert_eq!(fs::read(path).unwrap(), source);
    }

    #[test]
    fn legacy_drafts_file_is_not_read_or_migrated() {
        let (root, _dep, session, _path) = setup();
        fs::write(
            root.path().join("target/drafts.json"),
            "invalid old draft data",
        )
        .unwrap();
        let config = session.config.clone();
        drop(session);
        let session =
            Session::open(root.path().into(), root.path().join("target"), config).unwrap();
        assert!(session.buffers.is_empty());
        assert!(!session.metadata_file.exists());
    }

    fn editor(session: &mut Session, path: &str) -> OverrideEditor {
        let revision = session.buffer(path).unwrap().revision;
        session
            .open_override_editor(OverrideEditorTarget::Finding {
                id: "finding".into(),
                action: "justification".into(),
                revision,
                generation: session.analysis.generation,
            })
            .unwrap()
    }

    #[test]
    fn stale_analysis_does_not_block_overrides_for_unchanged_dependency_source() {
        let (root, _dep, mut session, path) = setup();
        let local = root.path().join("workspace.rs");
        fs::write(&local, "fn workspace() {}\n").unwrap();
        let buffer = session.buffer(local.to_str().unwrap()).unwrap();
        session
            .save_source(
                &buffer.path,
                buffer.revision,
                "// changed\nfn workspace() {}\n".into(),
            )
            .unwrap();
        assert!(session.analysis.stale);
        let context = editor(&mut session, &path);
        session
            .commit_override(
                &context.token,
                &context.destination,
                Some("saved.toml"),
                "// SAFETY: unchanged dependency is valid".into(),
            )
            .unwrap();
        assert!(session.analysis.stale);
        assert!(
            fs::read_to_string(root.path().join("saved.toml"))
                .unwrap()
                .contains("unchanged dependency is valid")
        );
    }

    #[test]
    fn direct_save_creates_named_file_and_allows_edits_without_reanalysis() {
        let (root, _dep, mut session, path) = setup();
        let original = fs::read(&path).unwrap();
        let context = editor(&mut session, &path);
        assert!(!context.destinations[0].exists);
        for filename in [
            None,
            Some(""),
            Some("../outside.toml"),
            Some("sniff-test.toml"),
        ] {
            assert!(
                session
                    .commit_override(
                        &context.token,
                        &context.destination,
                        filename,
                        "// SAFETY: valid".into()
                    )
                    .is_err()
            );
        }

        let (buffer, destination) = session
            .commit_override(
                &context.token,
                &context.destination,
                Some("custom.toml"),
                "// SAFETY: checked".into(),
            )
            .unwrap();
        assert_eq!(
            destination,
            root.path()
                .canonicalize()
                .unwrap()
                .join("custom.toml")
                .to_string_lossy()
        );
        assert!(session.analysis.overrides_changed);
        assert!(!session.analysis.stale);
        assert!(!session.analysis.running);
        assert!(!buffer.saved_overrides.is_empty());

        assert!(
            fs::read_to_string(root.path().join("sniff-test.toml"))
                .unwrap()
                .contains("custom.toml")
        );
        let context = session
            .open_override_editor(OverrideEditorTarget::Saved {
                path: path.clone(),
                revision: buffer.revision,
                index: 0,
            })
            .unwrap();
        assert!(context.destinations[0].exists);
        session
            .commit_override(
                &context.token,
                &context.destination,
                None,
                "// SAFETY: revised".into(),
            )
            .unwrap();
        let saved = fs::read_to_string(destination).unwrap();
        assert!(saved.contains("SAFETY: revised"));
        assert!(!saved.contains("SAFETY: checked"));
        assert_eq!(fs::read(path).unwrap(), original);
    }

    #[test]
    fn direct_save_preserves_other_saved_contributions_and_uses_existing_destination() {
        let (root, _dep, mut session, path) = setup();
        fs::write(
            root.path().join("sniff-test.toml"),
            "[contracts]\noverride-files=[\"one.toml\",\"two.toml\"]\n",
        )
        .unwrap();
        let original = "# keep\n[overrides]\n\"other::api\"=\"# Safety\\nExisting\"\n";
        for file in ["one.toml", "two.toml"] {
            fs::write(root.path().join(file), original).unwrap();
        }
        let context = editor(&mut session, &path);
        let destination = context.destinations[1].path.clone();
        let (buffer, _) = session
            .commit_override(
                &context.token,
                &destination,
                None,
                "// SAFETY: first contribution".into(),
            )
            .unwrap();
        let mut other = session.analysis.findings[0].clone();
        other.id = "other".into();
        other.effect = Some("panic".into());
        other.audit.as_mut().unwrap().effect = "panic".into();
        other.audit.as_mut().unwrap().justification = "PANIC".into();
        session.analysis.findings.push(other);
        let context = session
            .open_override_editor(OverrideEditorTarget::Finding {
                id: "other".into(),
                action: "justification".into(),
                revision: buffer.revision,
                generation: session.analysis.generation,
            })
            .unwrap();
        let (buffer, _) = session
            .commit_override(
                &context.token,
                &destination,
                None,
                "// PANIC: second contribution".into(),
            )
            .unwrap();
        assert_eq!(buffer.saved_overrides.len(), 2);
        let context = session
            .open_override_editor(OverrideEditorTarget::Saved {
                path,
                revision: buffer.revision,
                index: 0,
            })
            .unwrap();
        assert_eq!(context.destination, destination);
        session
            .commit_override(
                &context.token,
                &context.destination,
                None,
                "// SAFETY: revised contribution".into(),
            )
            .unwrap();
        let saved = fs::read_to_string(destination).unwrap();
        assert!(
            saved.contains("# keep")
                && saved.contains("other::api")
                && saved.contains("revised contribution")
                && saved.contains("second contribution")
        );
        assert!(!saved.contains("first contribution"));
        assert_eq!(
            fs::read_to_string(root.path().join("one.toml")).unwrap(),
            original
        );
    }

    #[test]
    fn missing_saved_override_file_can_be_recreated_under_a_new_name() {
        let (root, _dep, mut session, path) = setup();
        let context = editor(&mut session, &path);
        let (buffer, destination) = session
            .commit_override(
                &context.token,
                &context.destination,
                Some("original.toml"),
                "// SAFETY: original explanation".into(),
            )
            .unwrap();
        fs::remove_file(destination).unwrap();
        let context = session
            .open_override_editor(OverrideEditorTarget::Saved {
                path,
                revision: buffer.revision,
                index: 0,
            })
            .unwrap();
        assert!(!context.destinations[0].exists);
        let (buffer, destination) = session
            .commit_override(
                &context.token,
                &context.destination,
                Some("replacement.toml"),
                "// SAFETY: new explanation".into(),
            )
            .unwrap();
        assert_eq!(buffer.saved_overrides[0].destination, destination);
        let saved = fs::read_to_string(destination).unwrap();
        assert!(saved.contains("new explanation") && !saved.contains("original explanation"));
        let config = fs::read_to_string(root.path().join("sniff-test.toml")).unwrap();
        assert!(config.contains("replacement.toml") && !config.contains("original.toml"));
    }

    #[test]
    fn direct_save_rejects_conflicts_and_invalid_documents_without_drafts() {
        let (root, _dep, mut session, path) = setup();
        let context = editor(&mut session, &path);
        for document in [
            "// SAFETY: ",
            "// PANIC: wrong heading",
            "// SAFETY: reason\nfn injected() {}",
        ] {
            assert!(
                session
                    .commit_override(
                        &context.token,
                        &context.destination,
                        Some("custom.toml"),
                        document.into()
                    )
                    .is_err()
            );
        }
        fs::write(root.path().join("custom.toml"), "# created concurrently\n").unwrap();
        assert!(
            session
                .commit_override(
                    &context.token,
                    &context.destination,
                    Some("custom.toml"),
                    "// SAFETY: checked".into()
                )
                .is_err()
        );
        assert_eq!(
            fs::read_to_string(root.path().join("custom.toml")).unwrap(),
            "# created concurrently\n"
        );
        fs::write(
            root.path().join("sniff-test.toml"),
            "# external configuration change\n",
        )
        .unwrap();
        assert!(
            session
                .commit_override(
                    &context.token,
                    &context.destination,
                    Some("other.toml"),
                    "// SAFETY: checked".into()
                )
                .is_err()
        );
        assert!(!root.path().join("other.toml").exists());
    }

    #[test]
    fn named_file_is_relative_to_active_configuration_and_replaces_missing_entry() {
        let (root, _dep, mut session, path) = setup();
        let settings = root.path().join("settings");
        fs::create_dir(&settings).unwrap();
        session.config.arguments = vec!["--manifest".into(), "settings/audit.toml".into()];
        fs::write(
            settings.join("audit.toml"),
            "# config comment\n[contracts]\noverride-files=[\"missing.toml\"]\n",
        )
        .unwrap();
        let context = editor(&mut session, &path);
        let (_, destination) = session
            .commit_override(
                &context.token,
                &context.destination,
                Some("chosen.toml"),
                "// SAFETY: checked".into(),
            )
            .unwrap();
        assert_eq!(
            Path::new(&destination),
            settings.canonicalize().unwrap().join("chosen.toml")
        );
        let config = fs::read_to_string(settings.join("audit.toml")).unwrap();
        assert!(config.contains("# config comment") && config.contains("chosen.toml"));
        assert!(!config.contains("missing.toml"));
        assert!(!root.path().join("chosen.toml").exists());
    }

    #[test]
    fn failed_session_persistence_rolls_back_override_and_configuration() {
        let (root, _dep, mut session, path) = setup();
        let context = editor(&mut session, &path);
        session.metadata_file = root.path().join("target"); // Renaming a file over a directory must fail.
        assert!(
            session
                .commit_override(
                    &context.token,
                    &context.destination,
                    Some("custom.toml"),
                    "// SAFETY: checked".into()
                )
                .is_err()
        );
        assert!(!root.path().join("custom.toml").exists());
        assert!(!root.path().join("sniff-test.toml").exists());
        assert!(session.buffer(&path).unwrap().saved_overrides.is_empty());
        assert!(!session.analysis.overrides_changed);
    }

    #[test]
    fn direct_save_checks_file_source_generation_and_revision_snapshots() {
        let (root, _dep, mut session, path) = setup();
        fs::write(
            root.path().join("sniff-test-overrides.toml"),
            "# existing\n",
        )
        .unwrap();
        let context = editor(&mut session, &path);
        fs::write(&context.destination, "# external edit\n").unwrap();
        assert!(
            session
                .commit_override(
                    &context.token,
                    &context.destination,
                    None,
                    "// SAFETY: checked".into()
                )
                .is_err()
        );
        let context = editor(&mut session, &path);
        session.analysis.generation += 1;
        assert!(
            session
                .commit_override(
                    &context.token,
                    &context.destination,
                    None,
                    "// SAFETY: checked".into()
                )
                .is_err()
        );
        let context = editor(&mut session, &path);
        session.buffers.get_mut(&path).unwrap().revision += 1;
        assert!(
            session
                .commit_override(
                    &context.token,
                    &context.destination,
                    None,
                    "// SAFETY: checked".into()
                )
                .is_err()
        );
        let context = editor(&mut session, &path);
        fs::write(&path, "changed dependency").unwrap();
        assert!(
            session
                .commit_override(
                    &context.token,
                    &context.destination,
                    None,
                    "// SAFETY: checked".into()
                )
                .is_err()
        );
        assert_eq!(
            fs::read_to_string(context.destination).unwrap(),
            "# external edit\n"
        );
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
                .save_source(&buffer.path, buffer.revision, "changed".into())
                .is_err()
        );
        assert_eq!(fs::read_to_string(source).unwrap(), "fn dependency() {}\n");
    }
}
