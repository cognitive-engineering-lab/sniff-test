//! Shared auditing workflow. No HTTP, terminal, browser, or rustc dependencies.
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sniff_test_report::{
    AnalysisArtifactReport, Location, MarkerAssociation, REPORT_FORMAT_VERSION, SemanticFacts,
    TraceStep, content_hash,
};
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
    pub trace: Vec<TraceStep>,
    pub targets: Vec<EditTarget>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditTarget {
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
                    action: "justification".into(),
                    location: location.clone(),
                });
            }
        }
    }
    AuditMetadata {
        effect: facts.effect,
        obligation: facts.obligation.unwrap_or_default(),
        justification: facts.justification.unwrap_or_default(),
        source: facts.source,
        root: facts.root,
        contract: facts.contract,
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
}
#[derive(Debug, Clone, Default, Serialize)]
pub struct Analysis {
    pub generation: u64,
    pub running: bool,
    pub stale: bool,
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
            let audit = data
                .get("semantics")
                .map(|v| serde_json::from_value::<SemanticFacts>(v.clone()))
                .transpose()?
                .map(|facts| adapt_semantics(facts, &data));
            findings.push(Finding {
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
    pub original: String,
    pub content: String,
    pub revision: u64,
    pub writable: bool,
    pub conflict: bool,
}
impl Buffer {
    pub fn dirty(&self) -> bool {
        self.original != self.content
    }
}

pub struct Session {
    pub root: PathBuf,
    pub config: AnalysisConfig,
    pub analysis: Analysis,
    buffers: BTreeMap<String, Buffer>,
    draft_file: PathBuf,
    allowed_external: BTreeSet<PathBuf>,
    definition_sources: BTreeSet<PathBuf>,
    _lock: fs::File,
}
impl Session {
    pub fn open(root: PathBuf, target: PathBuf, config: AnalysisConfig) -> Result<Self> {
        let root = root.canonicalize()?;
        fs::create_dir_all(&target)?;
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(target.join("session.lock"))?;
        fs2::FileExt::try_lock_exclusive(&lock)
            .context("another audit session is using these drafts")?;
        let draft_file = target.join("drafts.json");
        let mut buffers: BTreeMap<String, Buffer> = if draft_file.exists() {
            serde_json::from_slice(&fs::read(&draft_file)?)
                .context("cannot restore audit drafts")?
        } else {
            BTreeMap::new()
        };
        for buffer in buffers.values_mut() {
            buffer.conflict =
                fs::read_to_string(&buffer.path).ok().as_ref() != Some(&buffer.original);
            buffer.writable = Path::new(&buffer.path)
                .canonicalize()
                .is_ok_and(|p| p.starts_with(&root));
        }
        Ok(Self {
            root,
            config,
            analysis: Analysis {
                stale: true,
                status: "not-run".into(),
                ..Default::default()
            },
            buffers,
            draft_file,
            allowed_external: BTreeSet::new(),
            definition_sources: BTreeSet::new(),
            _lock: lock,
        })
    }
    fn persist(&self) -> Result<()> {
        let dirty: BTreeMap<_, _> = self.buffers.iter().filter(|(_, b)| b.dirty()).collect();
        atomic_write(&self.draft_file, &serde_json::to_vec(&dirty)?)
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
            path.starts_with(&self.root)
                || (!write
                    && (self.allowed_external.contains(&path)
                        || self.definition_sources.contains(&path))),
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
        let resolved = self.checked_path(path, false)?;
        let key = resolved.to_string_lossy().into_owned();
        let disk = fs::read_to_string(&resolved).context("source is not readable UTF-8")?;
        let buffer = self.buffers.entry(key.clone()).or_insert_with(|| Buffer {
            path: key,
            original: disk.clone(),
            content: disk.clone(),
            revision: 0,
            writable: resolved.starts_with(&self.root),
            conflict: false,
        });
        if !buffer.dirty() && buffer.original != disk {
            buffer.original = disk.clone();
            buffer.content = disk.clone();
            buffer.revision += 1;
            self.analysis.stale = true;
        }
        buffer.conflict = buffer.original != disk;
        Ok(buffer.clone())
    }
    pub fn update(&mut self, path: &str, revision: u64, content: String) -> Result<Buffer> {
        ensure!(
            !self.analysis.running,
            "wait for analysis to finish before editing"
        );
        self.checked_path(path, true)?;
        let mut buffer = self.buffer(path)?;
        ensure!(
            buffer.revision == revision,
            "draft revision conflict; reload the buffer"
        );
        buffer.content = content;
        buffer.revision += 1;
        let previous = self.buffers.insert(buffer.path.clone(), buffer.clone());
        if let Err(error) = self.persist() {
            if let Some(previous) = previous {
                self.buffers.insert(previous.path.clone(), previous);
            }
            return Err(error);
        }
        Ok(buffer)
    }
    pub fn drafts(&mut self) -> Vec<Buffer> {
        for buffer in self.buffers.values_mut() {
            buffer.conflict =
                fs::read_to_string(&buffer.path).ok().as_ref() != Some(&buffer.original);
        }
        self.buffers
            .values()
            .filter(|b| b.dirty())
            .cloned()
            .collect()
    }
    pub fn diff(&mut self, path: &str) -> Result<String> {
        let b = self.buffer(path)?;
        Ok(similar::TextDiff::from_lines(&b.original, &b.content)
            .unified_diff()
            .header(&b.path, &b.path)
            .to_string())
    }
    pub fn discard(&mut self, path: &str, revision: u64) -> Result<()> {
        ensure!(!self.analysis.running, "wait for analysis to finish");
        let key = if self.buffers.contains_key(path) {
            path.to_owned()
        } else {
            self.checked_path(path, true)?
                .to_string_lossy()
                .into_owned()
        };
        let path = key.as_str();
        let b = self.buffers.get(path).context("unknown draft")?;
        ensure!(b.revision == revision, "draft revision conflict");
        let removed = self.buffers.remove(path);
        if let Err(error) = self.persist() {
            if let Some(b) = removed {
                self.buffers.insert(path.into(), b);
            }
            return Err(error);
        }
        Ok(())
    }
    pub fn apply(&mut self, path: &str, revision: u64) -> Result<()> {
        ensure!(!self.analysis.running, "wait for analysis to finish");
        let resolved = self.checked_path(path, true)?;
        let b = self.buffer(path)?;
        ensure!(b.revision == revision, "draft revision conflict");
        ensure!(
            !b.conflict,
            "source changed outside audit; preserve your draft and resolve the conflict first"
        );
        ensure!(
            fs::read_to_string(&resolved)? == b.original,
            "source changed before apply"
        );
        atomic_write(&resolved, b.content.as_bytes())?;
        let saved = self.buffers.get_mut(&b.path).unwrap();
        saved.original = saved.content.clone();
        saved.revision += 1;
        self.analysis.stale = true;
        self.persist()
    }
    pub fn begin_analysis(&mut self) -> Result<AnalysisConfig> {
        ensure!(!self.analysis.running, "analysis already running");
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
                            Path::new(&target.location.path)
                                .canonicalize()
                                .is_ok_and(|path| path.starts_with(&self.root))
                        });
                    }
                }
                for finding in &findings {
                    if let Some(a) = &finding.audit {
                        for location in a
                            .source
                            .iter()
                            .chain(a.root.iter())
                            .chain(a.contract.iter())
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
                self.analysis.findings = findings;
                self.analysis.stale = false;
            }
            Err(error) => {
                self.analysis.status = "failed".into();
                self.analysis.stale = true;
                self.analysis.log.push_str(&format!("\n{error}"));
            }
        }
    }
    /// Prepare an editor transaction without changing buffers or source files.
    pub fn prepare_template(
        &mut self,
        id: &str,
        action: &str,
        revision: u64,
    ) -> Result<TemplateEdit> {
        ensure!(
            !self.analysis.running && !self.analysis.stale,
            "reanalyze saved source before inserting documentation"
        );
        let audit = self
            .analysis
            .findings
            .iter()
            .find(|f| f.id == id)
            .and_then(|f| f.audit.clone())
            .context("finding no longer has source metadata")?;
        let target = audit
            .targets
            .iter()
            .find(|t| t.action == action)
            .context("no verified attachment location; edit source manually")?;
        self.checked_path(&target.location.path, true)?;
        let buffer = self.buffer(&target.location.path)?;
        ensure!(
            buffer.revision == revision && !buffer.dirty() && !buffer.conflict,
            "apply or discard edits and reanalyze before inserting a template"
        );
        ensure!(
            content_hash(buffer.content.as_bytes()) == target.location.hash,
            "source changed since analysis; reanalyze"
        );
        template_edit(&buffer, target, &audit)
    }

    pub fn propose(
        &mut self,
        id: &str,
        action: &str,
        explanation: &str,
        revision: u64,
    ) -> Result<Buffer> {
        ensure!(
            !self.analysis.running && !self.analysis.stale,
            "reanalyze saved source before generating documentation"
        );
        ensure!(!explanation.trim().is_empty(), "write an explanation first");
        let finding = self
            .analysis
            .findings
            .iter()
            .find(|f| f.id == id)
            .context("finding no longer exists")?;
        let audit = finding
            .audit
            .clone()
            .context("this finding has no editable source metadata")?;
        let target = audit
            .targets
            .iter()
            .find(|t| t.action == action)
            .context("this action requires manual source editing")?;
        let buffer = self.buffer(&target.location.path)?;
        ensure!(
            !buffer.dirty() && !buffer.conflict && buffer.revision == revision,
            "apply or discard this file's draft and reanalyze before generating another proposal"
        );
        ensure!(
            content_hash(buffer.original.as_bytes()) == target.location.hash,
            "source changed since analysis; reanalyze"
        );
        let content = documentation_edit(
            &buffer.content,
            &target.location,
            action,
            &audit,
            explanation,
        )?;
        self.update(&buffer.path, revision, content)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TemplateEdit {
    pub path: String,
    pub revision: u64,
    pub start: usize,
    pub end: usize,
    pub text: String,
    pub cursor: usize,
}

fn template_edit(
    buffer: &Buffer,
    target: &EditTarget,
    audit: &AuditMetadata,
) -> Result<TemplateEdit> {
    let source = &buffer.content;
    let start = target.location.start;
    ensure!(
        start <= source.len() && source.is_char_boundary(start),
        "source position unavailable"
    );
    let line_start = source[..start].rfind('\n').map_or(0, |i| i + 1);
    // Existing contiguous documentation is an editing destination, not another insertion.
    let needle = if target.action == "justification" {
        format!("// {}:", audit.justification.trim_end_matches(':'))
    } else {
        format!("/// # {}", audit.obligation.trim_start_matches('#').trim())
    };
    let mut offset = line_start;
    for line in source[..line_start].split_inclusive('\n').rev() {
        offset -= line.len();
        let trimmed = line.trim();
        if !(trimmed.starts_with("//") || (trimmed.starts_with("#[") && trimmed.ends_with(']'))) {
            break;
        }
        if trimmed.starts_with(&needle) && (target.action == "justification" || trimmed == needle) {
            let cursor = offset + line.trim_end_matches(['\r', '\n']).len();
            return Ok(TemplateEdit {
                path: buffer.path.clone(),
                revision: buffer.revision,
                start: cursor,
                end: cursor,
                text: String::new(),
                cursor,
            });
        }
    }
    let changed = documentation_edit(source, &target.location, &target.action, audit, "")?;
    // The documentation helper inserts a contiguous block without modifying existing source.
    let mut insertion = source
        .bytes()
        .zip(changed.bytes())
        .take_while(|(a, b)| a == b)
        .count();
    while !source.is_char_boundary(insertion) || !changed.is_char_boundary(insertion) {
        insertion -= 1;
    }
    let added = changed.len() - source.len();
    let text = changed[insertion..insertion + added].to_owned();
    ensure!(
        format!("{}{}{}", &source[..insertion], text, &source[insertion..]) == changed,
        "template cannot be inserted safely"
    );
    // Common-prefix insertion can leave the original indentation after the inserted newline.
    let line_end = changed[..insertion + added]
        .rfind('\n')
        .context("template has no line ending")?;
    let cursor = if changed.as_bytes().get(line_end.wrapping_sub(1)) == Some(&b'\r') {
        line_end - 1
    } else {
        line_end
    };
    Ok(TemplateEdit {
        path: buffer.path.clone(),
        revision: buffer.revision,
        start: insertion,
        end: insertion,
        text,
        cursor,
    })
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
    ensure!(
        prefix.trim().is_empty(),
        "target shares a line with other syntax; edit source manually"
    );
    let newline = if source.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut at = line_start;
    let comment;
    if action == "justification" {
        // Existing comments may be extending a marker. Do not silently create a second marker.
        let preceding = source[..line_start].trim_end();
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
        // Walk contiguous outer docs and single-line attributes. Complex attributes require manual editing.
        let mut docs_start = line_start;
        for line in source[..line_start].split_inclusive('\n').rev() {
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
        at = docs_start;
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
    fn session(dir: &Path) -> Session {
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
    fn metadata(location: Location) -> AuditMetadata {
        AuditMetadata {
            effect: "allocation".into(),
            obligation: "Allocations".into(),
            justification: "ALLOC".into(),
            source: Some(location.clone()),
            root: Some(location),
            contract: None,
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
            effect: "custom".into(),
            obligation: Some("Custom".into()),
            justification: Some("CUSTOM".into()),
            source: Some(location.clone()),
            root: Some(location.clone()),
            enclosing_function: Some(location.clone()),
            justification_site: Some(location.clone()),
            contract: None,
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
    fn json_report(name: &str, version: u32) -> String {
        serde_json::json!({"reason":"sniff-test-artifact","format-version":version,"tool-version":"test","rustc-version":"test","artifact":{"crate-name":name},"findings":[{"reason":"effect"}]}).to_string()
    }
    #[test]
    fn drafts_survive_restart_and_never_overwrite_external_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lib.rs");
        fs::write(&path, "old\r\nλ").unwrap();
        let path = path.to_str().unwrap();
        {
            let mut s = session(dir.path());
            let b = s.buffer(path).unwrap();
            s.update(path, b.revision, "new\r\nλ".into()).unwrap();
            assert_eq!(fs::read_to_string(path).unwrap(), "old\r\nλ");
            assert!(s.update(path, b.revision, "stale".into()).is_err());
        }
        let mut s = session(dir.path());
        let b = s.buffer(path).unwrap();
        assert_eq!(b.content, "new\r\nλ");
        fs::write(path, "external").unwrap();
        assert!(s.apply(path, b.revision).is_err());
        assert_eq!(fs::read_to_string(path).unwrap(), "external");
        assert!(s.drafts()[0].conflict);
        s.discard(path, b.revision).unwrap();
        assert_eq!(s.buffer(path).unwrap().content, "external");
    }
    #[test]
    fn apply_is_per_file_and_analysis_blocks_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lib.rs");
        fs::write(&path, "old").unwrap();
        let path = path.to_str().unwrap();
        let mut s = session(dir.path());
        let b = s.buffer(path).unwrap();
        let draft = s.update(path, b.revision, "new".into()).unwrap();
        s.begin_analysis().unwrap();
        assert!(s.apply(path, draft.revision).is_err());
        assert!(s.begin_analysis().is_err());
        s.finish_analysis(Err(anyhow::anyhow!("compiler failed")));
        s.apply(path, draft.revision).unwrap();
        assert_eq!(fs::read_to_string(path).unwrap(), "new");
        assert!(s.drafts().is_empty());
        assert!(s.analysis.stale);
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
        assert!(s.update(path, buffer.revision, "changed".into()).is_err());
        assert!(s.apply(path, buffer.revision).is_err());
        s.allowed_external.clear();
        assert!(
            s.buffer(path).is_ok(),
            "report refresh must retain definition destinations"
        );
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
    fn templates_preserve_unicode_crlf_and_navigate_existing_sections() {
        for source in [
            "// λ\r\n#[inline]\r\npub fn allocate() {}\r\n",
            "/// # Allocations\r\n/// Existing λ.\r\n#[inline]\r\npub fn allocate() {}\r\n",
        ] {
            let location = Location {
                path: "lib.rs".into(),
                source_id: "id".into(),
                hash: content_hash(source.as_bytes()),
                start: source.find("pub fn").unwrap(),
                end: source.len(),
                available: true,
            };
            let audit = metadata(location.clone());
            let buffer = Buffer {
                path: "lib.rs".into(),
                original: source.into(),
                content: source.into(),
                revision: 1,
                writable: true,
                conflict: false,
            };
            let edit = template_edit(
                &buffer,
                &EditTarget {
                    action: "obligation".into(),
                    location,
                },
                &audit,
            )
            .unwrap();
            let updated = format!(
                "{}{}{}",
                &source[..edit.start],
                edit.text,
                &source[edit.end..]
            );
            assert_eq!(updated.matches("# Allocations").count(), 1);
            assert!(updated.is_char_boundary(edit.cursor));
            assert_eq!(buffer.content, source);
            if source.contains("# Allocations") {
                assert!(edit.text.is_empty());
            } else {
                assert!(updated.contains("/// # Allocations\r\n///\r\n/// \r\n"));
            }
        }
    }
    #[test]
    fn indented_template_cursor_is_after_marker_not_on_source_line() {
        let source = "fn f() {\r\n    allocate();\r\n}\r\n";
        let location = Location {
            path: "lib.rs".into(),
            source_id: "id".into(),
            hash: content_hash(source.as_bytes()),
            start: source.find("allocate").unwrap(),
            end: source.len(),
            available: true,
        };
        let audit = metadata(location.clone());
        let buffer = Buffer {
            path: "lib.rs".into(),
            original: source.into(),
            content: source.into(),
            revision: 1,
            writable: true,
            conflict: false,
        };
        let edit = template_edit(
            &buffer,
            &EditTarget {
                action: "justification".into(),
                location,
            },
            &audit,
        )
        .unwrap();
        let mut updated = format!(
            "{}{}{}",
            &source[..edit.start],
            edit.text,
            &source[edit.end..]
        );
        updated.insert_str(edit.cursor, "Capacity checked λ.");
        assert_eq!(
            updated,
            "fn f() {\r\n    // ALLOC: Capacity checked λ.\r\n    allocate();\r\n}\r\n"
        );
    }
}
