//! Saved audit contributions, not a substitute for effect analysis.
use super::*;
use proc_macro2::{TokenStream, TokenTree};
use std::ops::Range;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct AuditProgress {
    pub justified: bool,
    pub propagated: bool,
}

pub(super) struct SourceSnapshot {
    hash: String,
    content: String,
    lexical: Option<LexicalSource>,
}
struct LexicalSource {
    comments: BTreeMap<usize, String>,
    attributes: BTreeMap<usize, usize>,
}

/// Disk work can run without holding the shared audit session lock.
pub struct ProgressRefresh {
    revision: (u64, u64, usize),
    epoch: u64,
    paths: Vec<(String, PathBuf)>,
}
pub struct ProgressRead {
    revision: (u64, u64, usize),
    epoch: u64,
    sources: BTreeMap<String, Option<(String, String)>>,
}
impl ProgressRefresh {
    pub fn read(self) -> ProgressRead {
        let sources = self
            .paths
            .into_iter()
            .map(|(key, path)| {
                let source = fs::read_to_string(path).ok().map(|content| {
                    let hash = content_hash(content.as_bytes());
                    (content, hash)
                });
                (key, source)
            })
            .collect();
        ProgressRead {
            revision: self.revision,
            epoch: self.epoch,
            sources,
        }
    }
}

impl Session {
    pub fn prepare_progress_refresh(&mut self) -> ProgressRefresh {
        self.reconcile_overrides();
        let revision = (
            self.analysis.results_revision,
            self.analysis.override_revision,
            self.analysis.findings.len(),
        );
        if self
            .progress_paths
            .as_ref()
            .is_none_or(|(r, n, _)| (*r, *n) != (revision.0, revision.2))
        {
            let paths: BTreeSet<_> = self
                .analysis
                .findings
                .iter()
                .filter_map(|f| f.audit.as_ref())
                .flat_map(|a| &a.targets)
                .map(|t| t.location.path.clone())
                .collect();
            self.progress_paths = Some((revision.0, revision.2, paths.into_iter().collect()));
        }
        ProgressRefresh {
            revision,
            epoch: self.progress_epoch,
            paths: self
                .progress_paths
                .as_ref()
                .unwrap()
                .2
                .iter()
                .filter_map(|key| {
                    self.checked_path(key, false)
                        .ok()
                        .map(|path| (key.clone(), path))
                })
                .collect(),
        }
    }

    /// Explicit mutations refresh synchronously before returning their new status.
    pub fn refresh_audit_progress(&mut self) {
        self.progress_epoch += 1;
        let read = self.prepare_progress_refresh().read();
        self.apply_progress_refresh(read, true);
    }

    /// Ignore obsolete background reads; only changed sources need lexical inspection.
    pub fn apply_progress_refresh(&mut self, read: ProgressRead, force: bool) {
        let revision = (
            self.analysis.results_revision,
            self.analysis.override_revision,
            self.analysis.findings.len(),
        );
        if revision != read.revision || self.progress_epoch != read.epoch {
            return;
        }
        let mut changed = BTreeSet::new();
        self.progress_sources.retain(|path, _| {
            let keep = read.sources.contains_key(path);
            if !keep {
                changed.insert(path.clone());
            }
            keep
        });
        for (path, source) in read.sources {
            let Some((content, hash)) = source else {
                if self.progress_sources.remove(&path).is_some() {
                    changed.insert(path);
                }
                continue;
            };
            if self
                .progress_sources
                .get(&path)
                .is_some_and(|s| s.hash == hash)
            {
                continue;
            }
            if self.progress_sources.contains_key(&path) {
                self.analysis.stale = true;
            }
            changed.insert(path.clone());
            let lexical = inspect_source(&content);
            self.progress_sources.insert(
                path,
                SourceSnapshot {
                    hash,
                    content,
                    lexical,
                },
            );
        }
        let rebuild = force || self.progress_revision != Some(revision);
        if !rebuild && changed.is_empty() {
            return;
        }
        self.progress_revision = Some(revision);
        let progress = self
            .analysis
            .findings
            .iter()
            .map(|finding| {
                if !rebuild
                    && finding.audit.as_ref().is_none_or(|a| {
                        !a.targets.iter().any(|t| changed.contains(&t.location.path))
                    })
                {
                    return (finding.id.clone(), self.audit_progress(&finding.id));
                }
                let mut progress = AuditProgress::default();
                if let Some(audit) = &finding.audit {
                    for target in &audit.targets {
                        let Some(source) = self.progress_sources.get(&target.location.path) else {
                            continue;
                        };
                        if !target.location.available || target.location.hash != source.hash {
                            continue;
                        }
                        let saved = if let Some(selector) = &target.selector {
                            self.buffers
                                .get(&target.location.path)
                                .is_some_and(|buffer| {
                                    buffer.saved_overrides.iter().any(|saved| {
                                        saved.location.hash == source.hash
                                            && saved.annotation.effect == audit.effect
                                            && saved.annotation.action == target.action
                                            && saved.annotation.selector.same_target(selector)
                                    })
                                })
                        } else {
                            attached_explanation(source, target, audit)
                        };
                        if saved {
                            match target.action.as_str() {
                                "justification" => progress.justified = true,
                                "obligation" => progress.propagated = true,
                                _ => {}
                            }
                        }
                    }
                }
                (finding.id.clone(), progress)
            })
            .collect();
        if self.progress != progress {
            self.progress = progress;
            self.analysis.audit_revision += 1;
        }
    }

    pub fn audit_progress(&self, id: &str) -> AuditProgress {
        self.progress.get(id).copied().unwrap_or_default()
    }
}

/// Token spans exclude raw strings and other literals. Then skip nested block
/// comments so only real, standalone line comments can attach to a target.
fn inspect_source(source: &str) -> Option<LexicalSource> {
    fn literals(tokens: TokenStream, source: &str, ranges: &mut Vec<Range<usize>>) {
        for token in tokens {
            match token {
                TokenTree::Group(group) => literals(group.stream(), source, ranges),
                TokenTree::Literal(literal) => {
                    let range = literal.span().byte_range();
                    // Doc comments are represented by synthetic string literals.
                    if source
                        .get(range.clone())
                        .is_some_and(|s| !s.starts_with('/'))
                    {
                        ranges.push(range);
                    }
                }
                _ => {}
            }
        }
    }
    let tokens = source.parse::<TokenStream>().ok()?;
    let attributes = outer_attribute_starts(tokens.clone(), source);
    let mut ranges = Vec::new();
    literals(tokens, source, &mut ranges);
    ranges.sort_by_key(|r| r.start);
    let mut ranges = ranges.into_iter().peekable();
    let bytes = source.as_bytes();
    let mut comments = BTreeMap::new();
    let mut at = 0;
    let mut depth = 0;
    while at < bytes.len() {
        while ranges.peek().is_some_and(|r| r.end <= at) {
            ranges.next();
        }
        if depth == 0
            && let Some(range) = ranges.peek().filter(|r| r.start == at)
        {
            at = range.end;
            continue;
        }
        if bytes[at..].starts_with(b"/*") {
            depth += 1;
            at += 2;
        } else if depth > 0 && bytes[at..].starts_with(b"*/") {
            depth -= 1;
            at += 2;
        } else if depth == 0 && bytes[at..].starts_with(b"//") {
            let end = source[at..].find('\n').map_or(source.len(), |n| at + n);
            let start = source[..at].rfind('\n').map_or(0, |n| n + 1);
            if source[start..at].trim().is_empty() {
                comments.insert(start, source[at..end].trim_end_matches('\r').to_owned());
            }
            at = end;
        } else {
            at += 1;
        }
    }
    Some(LexicalSource {
        comments,
        attributes,
    })
}

fn attached_explanation(
    source: &SourceSnapshot,
    target: &EditTarget,
    audit: &AuditMetadata,
) -> bool {
    let Some(lexical) = &source.lexical else {
        return false;
    };
    let Some(prefix) = source.content.get(..target.location.start) else {
        return false;
    };
    let line_start = prefix.rfind('\n').map_or(0, |n| n + 1);
    if !source.content[line_start..target.location.start]
        .trim()
        .is_empty()
    {
        return false;
    }
    let anchor = lexical
        .attributes
        .get(&line_start)
        .copied()
        .unwrap_or(line_start);
    let comments = &lexical.comments;
    let mut lines = Vec::new();
    let mut offset = anchor;
    for line in source.content[..anchor].split_inclusive('\n').rev() {
        offset -= line.len();
        let Some(comment) = comments.get(&offset) else {
            break;
        };
        lines.push(comment.as_str());
    }
    lines.reverse();
    if target.action == "justification" {
        let marker = audit.justification.trim().trim_end_matches(':');
        if marker.is_empty() {
            return false;
        }
        for (index, line) in lines.iter().enumerate() {
            if line.starts_with("///") || line.starts_with("//!") {
                continue;
            }
            let Some(body) = line
                .strip_prefix("//")
                .map(str::trim_start)
                .and_then(|s| s.strip_prefix(marker))
                .and_then(|s| s.strip_prefix(':'))
            else {
                continue;
            };
            if !body.trim().is_empty() {
                return true;
            }
            // A subsequent ordinary comment can supply a multiline explanation.
            if lines[index + 1..]
                .iter()
                .take_while(|l| !l.starts_with("///") && !l.starts_with("//!") && !marker_header(l))
                .any(|l| !l.trim_start_matches('/').trim().is_empty())
            {
                return true;
            }
        }
        false
    } else if target.action == "obligation" {
        let heading = format!(
            "# {}",
            audit.obligation.trim().trim_start_matches('#').trim()
        );
        let mut section = false;
        for line in lines {
            let Some(doc) = line
                .strip_prefix("///")
                .filter(|s| !s.starts_with('/'))
                .map(str::trim)
            else {
                section = false;
                continue;
            };
            if doc == heading {
                section = true;
                continue;
            }
            if doc.starts_with("# ") {
                section = false;
            }
            if section && !doc.is_empty() && !doc.starts_with('#') {
                return true;
            }
        }
        false
    } else {
        false
    }
}

fn marker_header(line: &str) -> bool {
    line.trim_start_matches('/')
        .trim()
        .split_once(':')
        .is_some_and(|(header, _)| {
            !header.is_empty() && header.chars().all(|c| c.is_ascii_uppercase() || c == '_')
        })
}

#[cfg(test)]
mod tests;
