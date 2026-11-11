//! Shared auditing workflow. No HTTP, terminal, browser, or rustc dependencies.
mod navigation;
mod overrides;
mod progress;
mod source_editor;
use anyhow::{Context, Result, bail, ensure};
pub use navigation::{FindingNavigation, NavigationLocation};
pub use overrides::{OverrideEditor, OverrideEditorTarget, SavedOverride};
pub use progress::AuditProgress;
pub use progress::{ProgressRead, ProgressRefresh};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sniff_test_report::{
    AnalysisArtifactReport, Location, MarkerAssociation, REPORT_FORMAT_VERSION, SemanticFacts,
    TraceStep, content_hash,
};
pub use source_editor::{SourceCommitResult, SourceEdit, SourceEditor, SourceEditorTarget};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output},
};

/// Presentation and action model owned by the auditing workflow, not the analyzer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditMetadata {
    pub effect: String,
    pub obligation: String,
    pub justification: String,
    pub source: Option<Location>,
    pub root: Option<Location>,
    pub contract: Option<Location>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obligation_documentation: Option<sniff_test_report::ObligationDocumentation>,
    pub trace: Vec<TraceStep>,
    pub targets: Vec<EditTarget>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditTarget {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<sniff_test_report::OverrideSelector>,
    pub action: String,
    pub location: Location,
}

fn adapt_semantics(facts: SemanticFacts, finding: &Value) -> AuditMetadata {
    let mut targets = Vec::new();
    let class = finding["finding"].as_str().unwrap_or_default();
    let source_kind = matches!(
        class,
        "concrete-operation" | "concrete-invocation" | "documented-obligation"
    );
    if source_kind {
        if facts.obligation.is_some() {
            if let Some(location) = facts.enclosing_function.as_ref().filter(|l| l.available) {
                targets.push(EditTarget {
                    selector: None,
                    action: "obligation".into(),
                    location: location.clone(),
                });
            }
        }
        let invocation = facts
            .trace
            .last()
            .is_some_and(|step| step.marker_association == MarkerAssociation::SourceInvocation);
        if facts.justification.is_some()
            && finding["owner"]["scope"] == "workspace"
            && (invocation || class == "concrete-operation")
        {
            if let Some(location) = facts.justification_site.as_ref().filter(|l| l.available) {
                targets.push(EditTarget {
                    selector: None,
                    action: "justification".into(),
                    location: location.clone(),
                });
            }
        }
    }
    targets.extend(facts.override_targets.into_iter().map(|t| EditTarget {
        action: t.action,
        location: t.location,
        selector: Some(t.selector),
    }));
    AuditMetadata {
        effect: facts.effect,
        obligation: facts.obligation.unwrap_or_default(),
        justification: facts.justification.unwrap_or_default(),
        source: facts.source,
        root: facts.root,
        contract: facts.contract,
        obligation_documentation: facts.obligation_documentation,
        trace: facts.trace,
        targets,
    }
}

#[derive(Debug, Clone)]
pub struct AnalysisConfig {
    pub executable: PathBuf,
    pub directory: PathBuf,
    pub arguments: Vec<String>,
}
impl AnalysisConfig {
    pub fn run(&self) -> Result<Output> {
        Command::new(&self.executable)
            .args(&self.arguments)
            .current_dir(&self.directory)
            .output()
            .context("could not start analyzer")
    }
}

/// Remove only frontend flags, never arguments after Cargo's `--` separator.
pub fn analysis_arguments(input: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut input = input.into_iter().peekable();
    let mut result = Vec::new();
    if input.peek().is_some_and(|a| a == "sniff-test") {
        input.next();
    }
    while let Some(arg) = input.next() {
        if arg == "--" {
            result.extend(["--message-format=json".into(), "--color=never".into(), arg]);
            result.extend(input);
            return result;
        }
        if matches!(arg.as_str(), "--audit" | "--message-format" | "--color") {
            input.next();
            continue;
        }
        if arg.starts_with("--audit=")
            || arg.starts_with("--message-format=")
            || arg.starts_with("--color=")
        {
            continue;
        }
        result.push(arg);
    }
    result.extend(["--message-format=json".into(), "--color=never".into()]);
    result
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_source: Option<sniff_test_report::DirectSourceKey>,
    pub id: String,
    pub crate_name: String,
    pub effect: Option<String>,
    pub kind: String,
    pub class: Option<String>,
    pub level: String,
    pub root: Option<String>,
    pub trace_id: Option<String>,
    pub reason: String,
    pub requirements: Vec<String>,
    pub missing_requirements: Vec<String>,
    pub display_trace: Vec<String>,
    pub audit: Option<AuditMetadata>,
    #[serde(default)]
    pub dependency: bool,
}
#[derive(Debug, Clone, Default, Serialize)]
pub struct Analysis {
    pub generation: u64,
    /// Changes when the finding set is replaced, rather than when a run starts.
    pub results_revision: u64,
    pub running: bool,
    pub stale: bool,
    pub overrides_changed: bool,
    pub override_revision: u64,
    pub audit_revision: u64,
    pub override_error: Option<String>,
    pub status: String,
    pub exit_code: Option<i32>,
    pub log: String,
    pub findings: Vec<Finding>,
}

pub fn parse_reports(stdout: &[u8]) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let mut artifacts = 0;
    for line in String::from_utf8_lossy(stdout).lines() {
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if value["reason"] != "sniff-test-artifact" {
            continue;
        }
        let report: AnalysisArtifactReport = serde_json::from_value(value)?;
        ensure!(
            report.format_version == REPORT_FORMAT_VERSION,
            "unsupported report version {}; expected {}",
            report.format_version,
            REPORT_FORMAT_VERSION
        );
        artifacts += 1;
        for data in report.findings {
            let facts = data
                .get("semantics")
                .map(|v| serde_json::from_value::<SemanticFacts>(v.clone()))
                .transpose()?;
            let direct_source = facts.as_ref().and_then(|facts| facts.direct_source.clone());
            let audit = facts.map(|facts| adapt_semantics(facts, &data));
            findings.push(Finding {
                direct_source,
                id: format!("{artifacts}:{}", findings.len()),
                crate_name: report.artifact.crate_name.clone(),
                effect: data["effect"].as_str().map(str::to_owned),
                kind: data["kind"].as_str().unwrap_or("unknown").to_owned(),
                class: data["finding"].as_str().map(str::to_owned),
                level: data["level"].as_str().unwrap_or("warn").to_owned(),
                root: data["root"].as_str().map(str::to_owned),
                trace_id: data["trace-id"].as_str().map(str::to_owned),
                reason: data["reason"].as_str().unwrap_or_default().to_owned(),
                requirements: string_list(&data["requirements"]),
                missing_requirements: string_list(&data["missing-requirements"]),
                display_trace: string_list(&data["trace"]),
                audit,
                dependency: data["owner"]["scope"] == "dependency",
            });
        }
    }
    ensure!(
        artifacts > 0,
        "analyzer produced no artifact reports; inspect the compiler output"
    );
    Ok(findings)
}

fn string_list(value: &Value) -> Vec<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Buffer {
    pub path: String,
    pub content: String,
    pub hash: String,
    pub revision: u64,
    pub writable: bool,
    #[serde(default)]
    pub saved_overrides: Vec<SavedOverride>,
}

pub struct Session {
    pub root: PathBuf,
    pub config: AnalysisConfig,
    pub analysis: Analysis,
    buffers: BTreeMap<String, Buffer>,
    metadata_file: PathBuf,
    allowed_external: BTreeSet<PathBuf>,
    definition_sources: BTreeSet<PathBuf>,
    dependency_sources: BTreeSet<PathBuf>,
    _lock: fs::File,
    pending_editor: Option<OverrideEditor>,
    pending_source_editor: Option<SourceEditor>,
    analysis_override_revision: u64,
    override_snapshot: Option<BTreeMap<String, Result<Option<String>, String>>>,
    navigation: BTreeMap<String, FindingNavigation>,
    progress: BTreeMap<String, AuditProgress>,
    progress_sources: BTreeMap<String, progress::SourceSnapshot>,
    progress_paths: Option<(u64, usize, Vec<String>)>,
    progress_revision: Option<(u64, u64, usize)>,
    progress_epoch: u64,
    finding_index: BTreeMap<String, usize>,
}
impl Session {
    pub fn finding(&self, id: &str) -> Option<&Finding> {
        self.finding_index
            .get(id)
            .and_then(|&i| self.analysis.findings.get(i))
            .filter(|f| f.id == id)
            .or_else(|| self.analysis.findings.iter().find(|f| f.id == id))
    }

    pub fn open(root: PathBuf, target: PathBuf, config: AnalysisConfig) -> Result<Self> {
        let root = root.canonicalize()?;
        fs::create_dir_all(&target)?;
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(target.join("session.lock"))?;
        fs2::FileExt::try_lock_exclusive(&lock)
            .context("another audit session is using this workspace")?;
        let metadata_file = target.join("saved-overrides.json");
        let saved: BTreeMap<String, Vec<SavedOverride>> = if metadata_file.exists() {
            serde_json::from_slice(&fs::read(&metadata_file)?)
                .context("cannot restore saved override metadata")?
        } else {
            BTreeMap::new()
        };
        let mut buffers = BTreeMap::new();
        for (path, mut saved_overrides) in saved {
            let Ok(content) = fs::read_to_string(&path) else {
                continue;
            };
            let hash = content_hash(content.as_bytes());
            saved_overrides.retain(|saved| saved.location.hash == hash);
            if saved_overrides.is_empty() {
                continue;
            }
            buffers.insert(
                path.clone(),
                Buffer {
                    path,
                    content,
                    hash,
                    revision: 0,
                    writable: false,
                    saved_overrides,
                },
            );
        }
        let mut session = Self {
            root,
            config,
            analysis: Analysis {
                stale: true,
                status: "not-run".into(),
                ..Default::default()
            },
            buffers,
            metadata_file,
            allowed_external: BTreeSet::new(),
            definition_sources: BTreeSet::new(),
            dependency_sources: BTreeSet::new(),
            _lock: lock,
            pending_editor: None,
            pending_source_editor: None,
            override_snapshot: None,
            analysis_override_revision: 0,
            navigation: BTreeMap::new(),
            progress: BTreeMap::new(),
            progress_sources: BTreeMap::new(),
            progress_paths: None,
            progress_revision: None,
            progress_epoch: 0,
            finding_index: BTreeMap::new(),
        };
        session.reconcile_overrides();
        Ok(session)
    }
    fn persist(&self) -> Result<()> {
        let saved: BTreeMap<_, _> = self
            .buffers
            .iter()
            .filter(|(_, buffer)| !buffer.saved_overrides.is_empty())
            .map(|(path, buffer)| (path, &buffer.saved_overrides))
            .collect();
        atomic_write(&self.metadata_file, &serde_json::to_vec(&saved)?)
    }

    fn checked_path(&self, path: &str, write: bool) -> Result<PathBuf> {
        let candidate = Path::new(path);
        let path = if candidate.is_absolute() {
            candidate.to_owned()
        } else {
            self.root.join(candidate)
        }
        .canonicalize()
        .context("source unavailable")?;
        ensure!(path.is_file(), "not a source file");
        ensure!(
            !write
                || !self.dependency_sources.contains(&path)
                    && self
                        .buffers
                        .get(path.to_string_lossy().as_ref())
                        .is_none_or(|b| b.writable),
            "dependency source is read-only"
        );
        ensure!(
            path.starts_with(&self.root)
                || (!write
                    && (self.allowed_external.contains(&path)
                        || self.definition_sources.contains(&path)
                        || self
                            .buffers
                            .get(path.to_string_lossy().as_ref())
                            .is_some_and(|b| !b.saved_overrides.is_empty()))),
            "source is outside this workspace"
        );
        Ok(path)
    }
    /// Admit a definition destination returned by the workspace language server.
    /// This grants read access only; normal workspace write checks still apply.
    pub fn allow_definition_source(&mut self, path: &Path) {
        if let Ok(path) = path.canonicalize()
            && path.is_file()
        {
            self.definition_sources.insert(path);
        }
    }

    pub fn buffer(&mut self, path: &str) -> Result<Buffer> {
        self.reconcile_overrides();
        let resolved = self.checked_path(path, false)?;
        let key = resolved.to_string_lossy().into_owned();
        let disk = fs::read_to_string(&resolved).context("source is not readable UTF-8")?;
        let buffer = self.buffers.entry(key.clone()).or_insert_with(|| Buffer {
            path: key,
            content: disk.clone(),
            hash: content_hash(disk.as_bytes()),
            revision: 0,
            writable: resolved.starts_with(&self.root)
                && !self.dependency_sources.contains(&resolved),
            saved_overrides: Vec::new(),
        });
        if self.dependency_sources.contains(&resolved) {
            buffer.writable = false;
        }
        if buffer.content != disk {
            buffer.content = disk.clone();
            buffer.hash = content_hash(disk.as_bytes());
            buffer.revision += 1;
            self.analysis.stale = true;
        }
        buffer
            .saved_overrides
            .retain(|saved| saved.location.hash == buffer.hash);
        Ok(buffer.clone())
    }
    /// Atomically save the editor snapshot without starting analysis.
    pub fn save_source(&mut self, path: &str, revision: u64, content: String) -> Result<Buffer> {
        ensure!(
            !self.analysis.running,
            "wait for analysis to finish before editing"
        );
        let resolved = self.checked_path(path, true)?;
        let key = resolved.to_string_lossy().into_owned();
        let buffer = self
            .buffers
            .get(&key)
            .context("open the source file before saving")?;
        ensure!(
            buffer.revision == revision,
            "source revision conflict; reload the file"
        );
        let disk = fs::read_to_string(&resolved)?;
        if disk != buffer.content {
            self.analysis.stale = true;
            bail!("Source changed outside audit. Copy your edits before reloading the file.");
        }
        if content == buffer.content {
            return Ok(buffer.clone());
        }
        let previous = buffer.content.clone();
        atomic_write(&resolved, content.as_bytes())?;
        self.map_saved_locations(&key, &previous, &content);
        let buffer = self.buffers.get_mut(&key).unwrap();
        buffer.hash = content_hash(content.as_bytes());
        buffer.content = content;
        buffer.revision += 1;
        self.analysis.stale = true;
        Ok(buffer.clone())
    }
    pub fn begin_analysis(&mut self) -> Result<AnalysisConfig> {
        ensure!(!self.analysis.running, "analysis already running");
        self.reconcile_overrides();
        self.analysis_override_revision = self.analysis.override_revision;
        self.analysis.running = true;
        self.analysis.status = "running".into();
        self.analysis.generation += 1;
        Ok(self.config.clone())
    }
    pub fn finish_analysis(&mut self, result: Result<Output>) {
        self.analysis.running = false;
        let output = match result {
            Ok(output) => output,
            Err(error) => {
                self.analysis.status = "failed".into();
                self.analysis.stale = true;
                self.analysis.log = error.to_string();
                return;
            }
        };
        self.analysis.exit_code = output.status.code();
        self.analysis.log = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter(|l| !l.contains("\"sniff-test-artifact\""))
                .collect::<Vec<_>>()
                .join("\n")
        );
        match parse_reports(&output.stdout) {
            Ok(mut findings) => {
                self.allowed_external.clear();
                for finding in &mut findings {
                    if let Some(audit) = &mut finding.audit {
                        audit.targets.retain(|target| {
                            target.selector.is_some()
                                || Path::new(&target.location.path)
                                    .canonicalize()
                                    .is_ok_and(|path| path.starts_with(&self.root))
                        });
                    }
                }
                for finding in &findings {
                    if let Some(a) = &finding.audit {
                        if finding.dependency {
                            for location in a.source.iter().chain(
                                a.targets
                                    .iter()
                                    .filter(|t| t.selector.is_some())
                                    .map(|t| &t.location),
                            ) {
                                if let Ok(path) = Path::new(&location.path).canonicalize() {
                                    self.dependency_sources.insert(path);
                                }
                            }
                        }
                        for location in a
                            .source
                            .iter()
                            .chain(a.root.iter())
                            .chain(a.contract.iter())
                            .chain(a.targets.iter().map(|t| &t.location))
                            .chain(a.trace.iter().filter_map(|s| s.location.as_ref()))
                        {
                            if let Ok(path) = Path::new(&location.path).canonicalize() {
                                self.allowed_external.insert(path);
                            }
                        }
                    }
                }
                let incomplete = findings
                    .iter()
                    .any(|f| f.class.as_deref() == Some("analysis-incomplete"));
                self.analysis.status = if !output.status.success() {
                    "failed"
                } else if incomplete {
                    "incomplete"
                } else {
                    "complete"
                }
                .into();
                self.navigation.clear();
                // The new reports consumed disk source. Old lexical snapshots
                // must not make the freshly completed analysis appear stale.
                self.progress_sources.clear();
                self.progress_revision = None;
                self.analysis.results_revision += 1;
                self.finding_index = findings
                    .iter()
                    .enumerate()
                    .map(|(i, f)| (f.id.clone(), i))
                    .collect();
                self.analysis.findings = findings;
                // Reanalysis consumed disk source. Refresh acknowledged snapshots so
                // opening an externally changed file does not invalidate that analysis.
                for buffer in self.buffers.values_mut() {
                    if let Ok(content) = fs::read_to_string(&buffer.path) {
                        if buffer.content != content {
                            buffer.hash = content_hash(content.as_bytes());
                            buffer.content = content;
                            buffer.revision += 1;
                        }
                        let hash = content_hash(buffer.content.as_bytes());
                        buffer
                            .saved_overrides
                            .retain(|saved| saved.location.hash == hash);
                    }
                }
                self.reconcile_overrides();
                self.analysis.stale = self.analysis.override_error.is_some()
                    || self.analysis.override_revision != self.analysis_override_revision;
                if output.status.success() && !self.analysis.stale {
                    self.analysis.overrides_changed = false;
                }
            }
            Err(error) => {
                self.analysis.status = "failed".into();
                self.analysis.stale = true;
                self.analysis.log.push_str(&format!("\n{error}"));
            }
        }
    }
}

/// Find attached outer attributes without mistaking brackets in strings or
/// comments for attribute boundaries. Offsets remain in original source bytes.
/// Index attached outer attributes in one token walk, including nested items.
/// Synthetic doc-comment attributes do not move the documentation anchor.
fn outer_attribute_starts(
    tokens: proc_macro2::TokenStream,
    source: &str,
) -> BTreeMap<usize, usize> {
    use proc_macro2::{Delimiter, TokenTree};
    fn visit(tokens: proc_macro2::TokenStream, source: &str, starts: &mut BTreeMap<usize, usize>) {
        let mut tokens = tokens.into_iter().peekable();
        let mut pending = None;
        while let Some(token) = tokens.next() {
            if matches!(&token, TokenTree::Punct(p) if p.as_char() == '#')
                && matches!(tokens.peek(), Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Bracket)
            {
                let start = token.span().byte_range().start;
                tokens.next();
                if source.get(start..).is_some_and(|s| s.starts_with('#')) {
                    pending.get_or_insert(start);
                }
                continue;
            }
            if let Some(attribute) = pending.take() {
                let start = token.span().byte_range().start.min(source.len());
                let line = source[..start].rfind('\n').map_or(0, |i| i + 1);
                let attribute_line = source[..attribute].rfind('\n').map_or(0, |i| i + 1);
                if attribute_line < line && source[attribute_line..attribute].trim().is_empty() {
                    starts.insert(line, attribute_line);
                }
            }
            if let TokenTree::Group(group) = token {
                visit(group.stream(), source, starts);
            }
        }
    }
    let mut starts = BTreeMap::new();
    visit(tokens, source, &mut starts);
    starts
}

fn outer_attribute_start(source: &str, line_start: usize) -> usize {
    if let Ok(tokens) = source.parse() {
        return outer_attribute_starts(tokens, source)
            .get(&line_start)
            .copied()
            .unwrap_or(line_start);
    }
    // Incomplete editor documents may not tokenize as a whole. Only template
    // editing uses this fallback; progress uses the cached lexical index.
    use syn::parse::Parser;
    let mut start = line_start;
    let mut offset = line_start;
    for line in source[..line_start].split_inclusive('\n').rev() {
        offset -= line.len();
        if line.trim_start().starts_with("#[")
            && syn::Attribute::parse_outer
                .parse_str(&source[offset..line_start])
                .is_ok()
        {
            start = offset;
        }
    }
    start
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file =
        tempfile::NamedTempFile::new_in(path.parent().context("missing parent directory")?)?;
    if let Ok(metadata) = fs::metadata(path) {
        file.as_file().set_permissions(metadata.permissions())?;
    }
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|e| e.error)?;
    Ok(())
}

/// Conservative insertion: unsupported layouts are left for the source editor.
pub fn documentation_edit(
    source: &str,
    location: &Location,
    action: &str,
    audit: &AuditMetadata,
    explanation: &str,
) -> Result<String> {
    ensure!(
        location.available
            && location.start <= source.len()
            && source.is_char_boundary(location.start),
        "source range unavailable"
    );
    let line_start = source[..location.start].rfind('\n').map_or(0, |i| i + 1);
    let prefix = &source[line_start..location.start];
    // Source markers attach by line, so an operation directly inside an unsafe
    // block can be justified above that block without rewriting the expression.
    let unsafe_block = action == "justification"
        && prefix
            .trim()
            .strip_prefix("unsafe")
            .and_then(|rest| rest.trim_start().strip_prefix('{'))
            .is_some_and(|rest| rest.trim().is_empty());
    ensure!(
        prefix.trim().is_empty() || unsafe_block,
        "target shares a line with other syntax; edit source manually"
    );
    let prefix = &prefix[..prefix.len() - prefix.trim_start().len()];
    let newline = if source.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let attribute_start = outer_attribute_start(source, line_start);
    let mut at = attribute_start;
    let comment;
    if action == "justification" {
        // Existing comments may be extending a marker. Do not silently create a second marker.
        let preceding = source[..attribute_start].trim_end();
        ensure!(
            !preceding
                .lines()
                .last()
                .is_some_and(|l| l.trim_start().starts_with("//")),
            "existing comment block: update its justification in the source editor"
        );
        comment = if explanation.is_empty() {
            format!(
                "{prefix}// {}: {newline}",
                audit.justification.trim_end_matches(':')
            )
        } else {
            format!(
                "{prefix}// {}:{newline}{}",
                audit.justification.trim_end_matches(':'),
                explanation
                    .lines()
                    .map(|l| format!("{prefix}// {l}{newline}"))
                    .collect::<String>()
            )
        };
    } else if action == "obligation" {
        // Include existing outer documentation before the attributes.
        let mut docs_start = attribute_start;
        for line in source[..attribute_start].split_inclusive('\n').rev() {
            let trimmed = line.trim();
            if trimmed.starts_with("///") || (trimmed.starts_with("#[") && trimmed.ends_with(']')) {
                docs_start -= line.len();
            } else {
                ensure!(
                    !trimmed.ends_with(']') && !trimmed.ends_with("*/"),
                    "complex documentation or attributes require manual editing"
                );
                break;
            }
        }
        let existing = &source[docs_start..line_start];
        ensure!(
            !existing.contains("#[doc"),
            "doc attributes require manual editing"
        );
        let heading = audit.obligation.trim_start_matches('#').trim();
        let mut offset = docs_start;
        let mut section = false;
        let mut found = false;
        // New sections follow existing documentation, before the attached attributes.
        at = attribute_start;
        for line in existing.split_inclusive('\n') {
            let doc = line.trim().strip_prefix("///").map(str::trim);
            if let Some(doc) = doc {
                if doc.starts_with("# ") {
                    if section {
                        break;
                    }
                    if doc.trim_start_matches('#').trim() == heading {
                        section = true;
                        found = true;
                    }
                }
                if section {
                    at = offset + line.len();
                }
            } else if section {
                break;
            }
            offset += line.len();
        }
        let body = if explanation.is_empty() {
            format!("{prefix}/// {newline}")
        } else {
            explanation
                .lines()
                .map(|l| format!("{prefix}/// {l}{newline}"))
                .collect::<String>()
        };
        comment = if found {
            format!("{prefix}///{newline}{body}")
        } else {
            format!("{prefix}/// # {heading}{newline}{prefix}///{newline}{body}")
        };
    } else {
        bail!("unknown documentation action");
    }
    Ok(format!("{}{}{}", &source[..at], comment, &source[at..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn session(dir: &Path) -> Session {
        Session::open(
            dir.to_owned(),
            dir.join("target/audit"),
            AnalysisConfig {
                executable: PathBuf::from("false"),
                directory: dir.to_owned(),
                arguments: vec![],
            },
        )
        .unwrap()
    }
    pub(super) fn metadata(location: Location) -> AuditMetadata {
        AuditMetadata {
            effect: "allocation".into(),
            obligation: "Allocations".into(),
            justification: "ALLOC".into(),
            source: Some(location.clone()),
            root: Some(location),
            contract: None,
            obligation_documentation: None,
            trace: vec![],
            targets: vec![],
        }
    }
    #[test]
    fn actions_are_derived_from_semantics_in_the_bridge() {
        use sniff_test_report::{MarkerAssociation, TraceKind};
        let location = Location {
            path: "lib.rs".into(),
            source_id: "file".into(),
            hash: "hash".into(),
            start: 0,
            end: 1,
            available: true,
        };
        let facts = SemanticFacts {
            direct_source: None,
            effect: "custom".into(),
            obligation: Some("Custom".into()),
            justification: Some("CUSTOM".into()),
            source: Some(location.clone()),
            root: Some(location.clone()),
            enclosing_function: Some(location.clone()),
            justification_site: Some(location.clone()),
            override_targets: Vec::new(),
            contract: None,
            obligation_documentation: None,
            trace: vec![TraceStep {
                caller: "caller".into(),
                target: None,
                kind: TraceKind::DirectCall,
                marker_association: MarkerAssociation::SourceInvocation,
                location: Some(location),
            }],
        };
        for (class, owner, marker, expected) in [
            (
                "concrete-invocation",
                "workspace",
                MarkerAssociation::SourceInvocation,
                2,
            ),
            (
                "concrete-invocation",
                "dependency",
                MarkerAssociation::SourceInvocation,
                1,
            ),
            (
                "concrete-invocation",
                "workspace",
                MarkerAssociation::None,
                1,
            ),
            (
                "concrete-operation",
                "workspace",
                MarkerAssociation::None,
                2,
            ),
            (
                "analysis-incomplete",
                "workspace",
                MarkerAssociation::SourceInvocation,
                0,
            ),
        ] {
            let mut facts = facts.clone();
            facts.trace[0].marker_association = marker;
            let finding = serde_json::json!({"finding":class,"owner":{"scope":owner}});
            assert_eq!(adapt_semantics(facts, &finding).targets.len(), expected);
        }
        let mut unavailable = facts;
        unavailable.justification_site.as_mut().unwrap().available = false;
        unavailable.enclosing_function.as_mut().unwrap().available = false;
        assert!(
            adapt_semantics(
                unavailable,
                &serde_json::json!({"finding":"concrete-operation","owner":{"scope":"workspace"}})
            )
            .targets
            .is_empty()
        );
    }

    #[test]
    fn forwards_arguments_without_recursing_or_changing_cargo_arguments() {
        let args = analysis_arguments(
            [
                "sniff-test",
                "--audit",
                "gui",
                "-e",
                "allocation",
                "--message-format",
                "human",
                "--",
                "--features",
                "gui",
            ]
            .map(str::to_owned),
        );
        assert_eq!(
            args,
            [
                "-e",
                "allocation",
                "--message-format=json",
                "--color=never",
                "--",
                "--features",
                "gui"
            ]
        );
        assert_eq!(
            analysis_arguments(["--audit=gui".into()]),
            ["--message-format=json", "--color=never"]
        );
    }
    #[test]
    fn reports_preserve_artifacts_and_reject_versions_and_missing_output() {
        let report = |name: &str, version| json_report(name, version);
        let input = format!(
            "cargo chatter\n{}\n{}\n",
            report("a", REPORT_FORMAT_VERSION),
            report("b", REPORT_FORMAT_VERSION)
        );
        let parsed = parse_reports(input.as_bytes()).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_ne!(parsed[0].id, parsed[1].id);
        assert_eq!(parsed[1].crate_name, "b");
        assert!(parse_reports(report("a", 0).as_bytes()).is_err());
        assert!(parse_reports(b"error: compilation failed").is_err());
    }
    pub(super) fn json_report(name: &str, version: u32) -> String {
        serde_json::json!({"reason":"sniff-test-artifact","format-version":version,"tool-version":"test","rustc-version":"test","artifact":{"crate-name":name},"findings":[{"reason":"effect"}]}).to_string()
    }
    #[test]
    fn source_saves_write_disk_and_reject_stale_or_external_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lib.rs");
        fs::write(&path, "old\r\nλ").unwrap();
        let path = path.to_str().unwrap();
        let mut s = session(dir.path());
        let b = s.buffer(path).unwrap();
        let saved = s.save_source(path, b.revision, "new\r\nλ".into()).unwrap();
        assert_eq!(fs::read_to_string(path).unwrap(), saved.content);
        assert!(s.analysis.stale);
        assert!(!s.metadata_file.exists());
        assert!(s.save_source(path, b.revision, "outdated".into()).is_err());
        fs::write(path, "external").unwrap();
        assert!(
            s.save_source(path, saved.revision, "overwrite".into())
                .is_err()
        );
        assert_eq!(fs::read_to_string(path).unwrap(), "external");
        assert_eq!(s.buffers[&saved.path].content, saved.content);
        let reloaded = s.buffer(path).unwrap();
        assert_eq!(reloaded.content, "external");
        assert!(reloaded.revision > saved.revision);
        drop(s);
        let mut s = session(dir.path());
        assert_eq!(s.buffer(path).unwrap().content, "external");
    }
    #[test]
    fn observed_edits_rebase_verified_targets_without_requiring_fresh_analysis() {
        let dir = tempfile::tempdir().unwrap();
        let source = "pub fn allocate() {\n    allocate();\n}\n";
        let path = dir.path().join("lib.rs");
        fs::write(&path, source).unwrap();
        let mut s = session(dir.path());
        let buffer = s.buffer(path.to_str().unwrap()).unwrap();
        let start = source.rfind("allocate()").unwrap();
        let call = Location {
            path: buffer.path.clone(),
            source_id: "source".into(),
            hash: buffer.hash.clone(),
            start,
            end: start + "allocate();".len(),
            available: true,
        };
        let mut function = call.clone();
        function.start = 0;
        function.end = source.find('{').unwrap() + 1;
        let mut audit = metadata(call.clone());
        audit.contract = Some(call.clone());
        audit.trace.push(TraceStep {
            caller: "work".into(),
            target: Some("allocate".into()),
            kind: sniff_test_report::TraceKind::DirectCall,
            marker_association: MarkerAssociation::SourceInvocation,
            location: Some(call.clone()),
        });
        audit.targets = vec![
            EditTarget {
                action: "justification".into(),
                location: call,
                selector: None,
            },
            EditTarget {
                action: "obligation".into(),
                location: function,
                selector: None,
            },
        ];
        let mut finding = parse_reports(json_report("local", REPORT_FORMAT_VERSION).as_bytes())
            .unwrap()
            .remove(0);
        finding.audit = Some(audit);
        let id = finding.id.clone();
        s.analysis.findings = vec![finding];
        s.analysis.stale = false;
        let content = format!("// λ\n{source}");
        let saved = s
            .save_source(&buffer.path, buffer.revision, content.clone())
            .unwrap();
        assert!(s.analysis.stale);
        for action in ["justification", "obligation"] {
            s.open_source_editor(SourceEditorTarget {
                id: id.clone(),
                action: action.into(),
                revision: saved.revision,
                generation: s.analysis.generation,
            })
            .unwrap();
        }
        let targets = &s.analysis.findings[0].audit.as_ref().unwrap().targets;
        assert_eq!(
            targets[0].location.start,
            content.rfind("allocate()").unwrap()
        );
        assert_eq!(targets[0].location.hash, saved.hash);
        let navigation = s.finding_navigation(&id).unwrap();
        for location in navigation
            .source
            .iter()
            .chain(navigation.root.iter())
            .chain(navigation.contract.iter())
            .chain(navigation.trace.iter().flatten())
        {
            assert_eq!(
                location.location.start,
                content.rfind("allocate()").unwrap()
            );
            assert_eq!(location.location.hash, saved.hash);
            assert!(!location.approximate);
        }
        assert_eq!(
            s.analysis.findings[0]
                .audit
                .as_ref()
                .unwrap()
                .source
                .as_ref()
                .unwrap()
                .start,
            start
        );

        let separated = format!("// another λ\n{content}// trailing note\n");
        let saved = s
            .save_source(&buffer.path, saved.revision, separated.clone())
            .unwrap();
        for action in ["justification", "obligation"] {
            s.open_source_editor(SourceEditorTarget {
                id: id.clone(),
                action: action.into(),
                revision: saved.revision,
                generation: s.analysis.generation,
            })
            .unwrap();
        }
        let changed = separated.replace("    allocate();", "    changed();");
        let saved = s
            .save_source(&buffer.path, saved.revision, changed)
            .unwrap();
        assert!(
            s.open_source_editor(SourceEditorTarget {
                id: id.clone(),
                action: "justification".into(),
                revision: saved.revision,
                generation: s.analysis.generation
            })
            .is_err()
        );
        s.open_source_editor(SourceEditorTarget {
            id: id.clone(),
            action: "obligation".into(),
            revision: saved.revision,
            generation: s.analysis.generation,
        })
        .unwrap();
        let navigation = s.finding_navigation(&id).unwrap();
        assert!(navigation.source.unwrap().approximate);
        assert!(navigation.trace[0].as_ref().unwrap().approximate);
        assert_eq!(navigation.contract.unwrap().location.hash, saved.hash);
        // Fresh analysis discards approximate destinations rather than mapping old reports again.
        s.begin_analysis().unwrap();
        let output = std::process::Output {
            status: std::process::Command::new("true").status().unwrap(),
            stdout: json_report("local", REPORT_FORMAT_VERSION).into_bytes(),
            stderr: vec![],
        };
        s.finish_analysis(Ok(output));
        assert!(s.navigation.is_empty());
    }

    #[test]
    fn source_saves_are_per_file_and_blocked_during_analysis() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("one.rs");
        let second = dir.path().join("two.rs");
        fs::write(&first, "one").unwrap();
        fs::write(&second, "two").unwrap();
        let mut s = session(dir.path());
        let buffer = s.buffer(first.to_str().unwrap()).unwrap();
        s.begin_analysis().unwrap();
        assert!(
            s.save_source(&buffer.path, buffer.revision, "edited".into())
                .is_err()
        );
        assert_eq!(fs::read_to_string(&first).unwrap(), "one");
        s.analysis.running = false;
        s.save_source(&buffer.path, buffer.revision, "edited".into())
            .unwrap();
        assert_eq!(fs::read_to_string(first).unwrap(), "edited");
        assert_eq!(fs::read_to_string(second).unwrap(), "two");
    }
    #[test]
    fn outside_files_and_symlinks_are_not_writable() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        let mut s = session(dir.path());
        assert!(s.buffer(outside.path().to_str().unwrap()).is_err());
        #[cfg(unix)]
        {
            let link = dir.path().join("escape.rs");
            std::os::unix::fs::symlink(outside.path(), &link).unwrap();
            assert!(s.buffer(link.to_str().unwrap()).is_err());
        }
    }
    #[test]
    fn language_server_destinations_grant_read_access_only() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        fs::write(outside.path(), "pub fn external() {}\n").unwrap();
        let mut s = session(dir.path());
        let path = outside.path().to_str().unwrap();
        assert!(s.buffer(path).is_err());
        s.allow_definition_source(outside.path());
        let buffer = s.buffer(path).unwrap();
        assert!(!buffer.writable);
        assert!(
            s.save_source(path, buffer.revision, "changed".into())
                .is_err()
        );
        s.allowed_external.clear();
        assert!(
            s.buffer(path).is_ok(),
            "report refresh must retain definition destinations"
        );
    }
    #[test]
    fn documentation_precedes_attached_multiline_attributes() {
        let attributes = "    #[cfg_attr(\r\n        feature = \"test\", allow(unused)\r\n    )]\r\n    #[custom(text = r#\"[λ]\"#)]\r\n";
        let source = format!("fn earlier() {{}}\r\n{attributes}    fn sample() {{}}\r\n");
        let location = Location {
            path: "lib.rs".into(),
            source_id: "id".into(),
            hash: content_hash(source.as_bytes()),
            start: source.find("fn sample").unwrap(),
            end: source.len(),
            available: true,
        };
        let audit = metadata(location.clone());
        for action in ["justification", "obligation"] {
            let edited =
                documentation_edit(&source, &location, action, &audit, "Checked λ.").unwrap();
            assert!(edited.starts_with("fn earlier() {}\r\n    //"));
            assert!(edited.contains(&format!("Checked λ.\r\n{attributes}")));
            assert!(edited.ends_with("    fn sample() {}\r\n"));
        }
    }

    #[test]
    fn justification_precedes_standalone_inline_unsafe_block() {
        for newline in ["\n", "\r\n"] {
            for indent in ["", "    ", "\t"] {
                for wrapper in ["unsafe { ", "unsafe{", "unsafe  {  "] {
                    let source = format!(
                        "fn sample() {{{newline}{indent}{wrapper}allocate() }}{newline}}}{newline}"
                    );
                    let start = source.find("allocate()").unwrap();
                    let location = Location {
                        path: "lib.rs".into(),
                        source_id: "id".into(),
                        hash: content_hash(source.as_bytes()),
                        start,
                        end: start + "allocate()".len(),
                        available: true,
                    };
                    let audit = metadata(location.clone());
                    let edited = documentation_edit(
                        &source,
                        &location,
                        "justification",
                        &audit,
                        "Checked λ.",
                    )
                    .unwrap();
                    assert_eq!(
                        edited,
                        format!(
                            "fn sample() {{{newline}{indent}// ALLOC:{newline}{indent}// Checked λ.{newline}{indent}{wrapper}allocate() }}{newline}}}{newline}"
                        )
                    );
                    assert!(
                        documentation_edit(&source, &location, "obligation", &audit, "Reason.")
                            .is_err()
                    );
                }
            }
        }
    }

    #[test]
    fn justification_refuses_other_inline_prefixes() {
        for prefix in [
            "let value = unsafe { ",
            "if ready { unsafe { ",
            "unsafe { earlier(); ",
            "unsafe { /* note */ ",
        ] {
            let source = format!("fn sample() {{\n    {prefix}allocate() }}\n}}\n");
            let start = source.find("allocate()").unwrap();
            let location = Location {
                path: "lib.rs".into(),
                source_id: "id".into(),
                hash: content_hash(source.as_bytes()),
                start,
                end: start + "allocate()".len(),
                available: true,
            };
            assert!(
                documentation_edit(
                    &source,
                    &location,
                    "justification",
                    &metadata(location.clone()),
                    "Reason."
                )
                .is_err()
            );
        }
    }

    #[test]
    fn guided_docs_extend_sections_preserve_crlf_and_refuse_ambiguous_layout() {
        let source = "/// Existing.\r\n/// # Allocations\r\n/// Old condition.\r\n#[inline]\r\npub fn allocate() {}\r\n";
        let location = Location {
            path: "lib.rs".into(),
            source_id: "id".into(),
            hash: content_hash(source.as_bytes()),
            start: source.find("pub fn").unwrap(),
            end: source.len(),
            available: true,
        };
        let audit = metadata(location.clone());
        let edited =
            documentation_edit(source, &location, "obligation", &audit, "New condition λ.")
                .unwrap();
        assert_eq!(edited.matches("# Allocations").count(), 1);
        assert!(edited.contains("/// New condition λ.\r\n#[inline]"));
        let mut bad = location.clone();
        bad.start = source.find("allocate").unwrap();
        assert!(documentation_edit(source, &bad, "obligation", &audit, "bad").is_err());
        let source = "    allocate();\r\n";
        let mut call = location;
        call.start = 4;
        call.end = 15;
        assert_eq!(
            documentation_edit(
                source,
                &call,
                "justification",
                &audit,
                "Requirements:\n- capacity: checked λ"
            )
            .unwrap(),
            "    // ALLOC:\r\n    // Requirements:\r\n    // - capacity: checked λ\r\n    allocate();\r\n"
        );
    }
    #[test]
    fn new_obligation_sections_follow_existing_docs() {
        for newline in ["\n", "\r\n"] {
            for prefix in ["", "    "] {
                for docs in [
                    "/// Existing λ.",
                    "/// Existing λ.\n///\n/// # Examples\n/// An example.",
                ] {
                    for attributes in [
                        "",
                        "#[inline]\n",
                        "#[cfg_attr(\n    test, allow(unused)\n)]\n",
                    ] {
                        let attached = format!("{docs}\n{attributes}")
                            .lines()
                            .map(|line| format!("{prefix}{line}{newline}"))
                            .collect::<String>();
                        let source = format!("{attached}{prefix}pub fn allocate() {{}}{newline}");
                        let location = Location {
                            path: "lib.rs".into(),
                            source_id: "id".into(),
                            hash: content_hash(source.as_bytes()),
                            start: source.find("pub fn").unwrap(),
                            end: source.len(),
                            available: true,
                        };
                        let audit = metadata(location.clone());
                        let at = source.find("#[").map_or_else(
                            || source.find("pub fn").unwrap() - prefix.len(),
                            |start| start - prefix.len(),
                        );
                        let expected = format!(
                            "{}{prefix}/// # Allocations{newline}{prefix}///{newline}{prefix}/// New condition λ.{newline}{}",
                            &source[..at],
                            &source[at..]
                        );
                        assert_eq!(
                            documentation_edit(
                                &source,
                                &location,
                                "obligation",
                                &audit,
                                "New condition λ."
                            )
                            .unwrap(),
                            expected
                        );
                    }
                }
            }
        }
    }
}
