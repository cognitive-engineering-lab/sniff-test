//! Verified source annotation edits. Source files remain authoritative.
use super::*;
use std::ops::Range;

#[derive(Debug, Clone, Deserialize)]
pub struct SourceEditorTarget {
    pub id: String,
    pub action: String,
    pub revision: u64,
    pub generation: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceEditor {
    pub token: String,
    pub document: String,
    pub can_remove: bool,
    pub destination: String,
    pub line: usize,
    pub obligation_documentation: Option<sniff_test_report::ObligationDocumentation>,
    #[serde(skip)]
    target: SourceEditorTarget,
    #[serde(skip)]
    range: Range<usize>,
    #[serde(skip)]
    original: String,
    #[serde(skip)]
    indent: String,
    #[serde(skip)]
    heading: String,
}

/// Exact byte edit committed to the source file, before its attachment locations are rebased.
#[derive(Debug, Clone, Serialize)]
pub struct SourceEdit {
    pub start: usize,
    pub end: usize,
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceCommitResult {
    pub buffer: Buffer,
    pub edit: SourceEdit,
}

impl Session {
    pub fn open_source_editor(&mut self, request: SourceEditorTarget) -> Result<SourceEditor> {
        ensure!(
            !self.analysis.running,
            "wait for analysis to finish before editing documentation"
        );
        ensure!(
            request.generation == self.analysis.generation,
            "Analysis changed; reopen the documentation editor."
        );
        let audit = self
            .finding(&request.id)
            .and_then(|f| f.audit.clone())
            .context("finding no longer has source metadata")?;
        let target = audit
            .targets
            .iter()
            .find(|t| t.action == request.action)
            .context("no verified attachment location; edit source manually")?;
        ensure!(
            target.selector.is_none() && target.location.available,
            "no verified source attachment; reanalyze"
        );
        self.checked_path(&target.location.path, true)?;
        let buffer = self.buffer(&target.location.path)?;
        ensure!(
            buffer.revision == request.revision && buffer.hash == target.location.hash,
            "source changed; reopen the documentation editor"
        );
        let (range, indent, heading) = annotation_range(&buffer.content, target, &audit)?;
        let can_remove = !range.is_empty();
        let document = if can_remove {
            buffer.content[range.clone()]
                .lines()
                .map(|l| l.strip_prefix(&indent).unwrap_or(l))
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            let mut location = target.location.clone();
            location.start = 0;
            let source = "fn target() {}\n";
            documentation_edit(source, &location, &request.action, &audit, "")?
                .strip_suffix(source)
                .context("invalid documentation template")?
                .trim_end_matches('\n')
                .to_owned()
        };
        let document = if request.action == "justification"
            && document
                .lines()
                .next()
                .is_some_and(|l| l.trim() == heading.trim_end_matches(':'))
        {
            document.replacen(heading.trim_end_matches(':'), &heading, 1)
        } else {
            document
        };
        let editor = SourceEditor {
            token: format!(
                "{:x}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_nanos()
            ),
            document,
            can_remove,
            destination: buffer.path,
            line: buffer.content[..range.start]
                .bytes()
                .filter(|b| *b == b'\n')
                .count()
                + 1,
            obligation_documentation: (request.action == "justification")
                .then_some(audit.obligation_documentation)
                .flatten(),
            target: request,
            range,
            original: buffer.content,
            indent,
            heading,
        };
        self.pending_editor = None;
        self.pending_source_editor = Some(editor.clone());
        Ok(editor)
    }

    pub fn commit_source_editor(
        &mut self,
        token: &str,
        document: Option<String>,
    ) -> Result<SourceCommitResult> {
        let editor = self
            .pending_source_editor
            .clone()
            .context("documentation editor expired; reopen it")?;
        ensure!(
            editor.token == token,
            "documentation editor expired; reopen it"
        );
        ensure!(
            !self.analysis.running && editor.target.generation == self.analysis.generation,
            "Analysis changed; reopen the documentation editor."
        );
        let buffer = self.buffer(&editor.destination)?;
        ensure!(
            buffer.revision == editor.target.revision && buffer.content == editor.original,
            "source changed; reopen the documentation editor"
        );
        let replacement = if let Some(document) = document {
            validate_document(&document, &editor.target.action, &editor.heading)?;
            let newline = if editor.original.contains("\r\n") {
                "\r\n"
            } else {
                "\n"
            };
            let separator = if editor.target.action == "obligation"
                && editor.range.is_empty()
                && editor.original[..editor.range.start]
                    .lines()
                    .last()
                    .and_then(|line| line.trim().strip_prefix("///"))
                    .is_some_and(|body| !body.trim().is_empty())
            {
                format!("{}///{newline}", editor.indent)
            } else {
                String::new()
            };
            separator
                + &document
                    .lines()
                    .map(|l| {
                        format!(
                            "{}{}{newline}",
                            editor.indent,
                            if l.trim().is_empty() {
                                if editor.target.action == "justification" {
                                    "//"
                                } else {
                                    "///"
                                }
                            } else {
                                l.trim_start()
                            }
                        )
                    })
                    .collect::<String>()
        } else {
            ensure!(editor.can_remove, "no saved source annotation to remove");
            String::new()
        };
        let mut content = editor.original;
        let edit = SourceEdit {
            start: editor.range.start,
            end: editor.range.end,
            text: replacement,
        };
        content.replace_range(edit.start..edit.end, &edit.text);
        let buffer = self.save_source(&editor.destination, editor.target.revision, content)?;
        self.pending_source_editor = None;
        Ok(SourceCommitResult { buffer, edit })
    }
}

/// Match only standalone lexical comments, stopping at other markers or contract sections.
fn annotation_range(
    source: &str,
    target: &EditTarget,
    audit: &AuditMetadata,
) -> Result<(Range<usize>, String, String)> {
    let at = target.location.start;
    ensure!(source.get(..at).is_some(), "source range unavailable");
    let line = source[..at].rfind('\n').map_or(0, |n| n + 1);
    let prefix = &source[line..at];
    let unsafe_block = target.action == "justification"
        && prefix
            .trim()
            .strip_prefix("unsafe")
            .and_then(|s| s.trim_start().strip_prefix('{'))
            .is_some_and(|s| s.trim().is_empty());
    ensure!(
        prefix.trim().is_empty() || unsafe_block,
        "target shares a line with other syntax; edit source manually"
    );
    let indent = prefix[..prefix.len() - prefix.trim_start().len()].to_owned();
    let lexical = progress::inspect_source(source)
        .context("cannot safely parse source; edit source manually")?;
    let anchor = lexical.attributes.get(&line).copied().unwrap_or(line);
    let heading = match target.action.as_str() {
        "justification" => format!("// {}:", audit.justification.trim_end_matches(':')),
        "obligation" => format!("/// # {}", audit.obligation.trim_start_matches('#').trim()),
        _ => bail!("unknown documentation action"),
    };
    let mut comments = Vec::new();
    let mut offset = anchor;
    for text in source[..anchor].split_inclusive('\n').rev() {
        offset -= text.len();
        let Some(comment) = lexical.comments.get(&offset) else {
            break;
        };
        comments.push((offset, offset + text.len(), comment.as_str()));
    }
    comments.reverse();
    let matches = comments
        .iter()
        .enumerate()
        .filter(|(_, (_, _, text))| {
            if target.action == "justification" {
                text.starts_with(&heading) || text.trim() == heading.trim_end_matches(':')
            } else {
                text.trim() == heading
            }
        })
        .map(|(i, _)| i)
        .collect::<Vec<_>>();
    ensure!(
        matches.len() <= 1,
        "ambiguous attached documentation; edit source manually"
    );
    if let Some(&index) = matches.first() {
        let end = comments[index + 1..]
            .iter()
            .find(|(_, _, text)| {
                if target.action == "justification" {
                    text.starts_with("///")
                        || text.starts_with("//!")
                        || progress::marker_header(text)
                } else {
                    !text.starts_with("///")
                        || text
                            .strip_prefix("///")
                            .is_some_and(|s| s.trim_start().starts_with("# "))
                }
            })
            .map_or(anchor, |(start, _, _)| *start);
        return Ok((comments[index].0..end, indent, heading));
    }
    // Let the established insertion helper reject unsupported documentation layouts.
    documentation_edit(source, &target.location, &target.action, audit, "")?;
    Ok((anchor..anchor, indent, heading))
}

fn validate_document(document: &str, action: &str, heading: &str) -> Result<()> {
    let body = document
        .trim_start()
        .strip_prefix(heading)
        .context("keep the documentation template heading")?;
    ensure!(
        document.lines().all(|line| {
            let line = line.trim_start();
            line.is_empty()
                || if action == "justification" {
                    line.starts_with("//") && !line.starts_with("///") && !line.starts_with("//!")
                } else {
                    line.starts_with("///") && !line.starts_with("////")
                }
        }),
        "only documentation comments are allowed"
    );
    ensure!(
        body.lines()
            .any(|l| !l.trim().trim_start_matches('/').trim().is_empty()),
        "write an explanation first"
    );
    // Never allow an edit to introduce another annotation that cannot be removed independently.
    ensure!(
        !body.lines().skip(1).any(|l| {
            if action == "justification" {
                progress::marker_header(l.trim())
            } else {
                l.trim()
                    .strip_prefix("///")
                    .is_some_and(|s| s.trim_start().starts_with("# "))
            }
        }),
        "edit only this documentation section"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{json_report, metadata, session};

    fn setup(
        source: &str,
        action: &str,
        needle: &str,
    ) -> (tempfile::TempDir, Session, SourceEditorTarget) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lib.rs");
        fs::write(&path, source).unwrap();
        let mut session = session(dir.path());
        let buffer = session.buffer(path.to_str().unwrap()).unwrap();
        let location = Location {
            path: buffer.path,
            source_id: "id".into(),
            hash: buffer.hash,
            start: source.rfind(needle).unwrap(),
            end: source.rfind(needle).unwrap() + needle.len(),
            available: true,
        };
        let mut audit = metadata(location.clone());
        audit.targets = vec![EditTarget {
            action: action.into(),
            location,
            selector: None,
        }];
        let mut finding = parse_reports(json_report("local", REPORT_FORMAT_VERSION).as_bytes())
            .unwrap()
            .remove(0);
        finding.audit = Some(audit);
        let request = SourceEditorTarget {
            id: finding.id.clone(),
            action: action.into(),
            revision: buffer.revision,
            generation: session.analysis.generation,
        };
        session.analysis.findings = vec![finding];
        (dir, session, request)
    }

    #[test]
    fn saves_reopens_replaces_and_removes_only_selected_annotation() {
        for newline in ["\n", "\r\n"] {
            for (action, needle, source, document) in [
                (
                    "justification",
                    "allocate();",
                    "fn f() {\n    allocate();\n}\n",
                    "// ALLOC: Valid λ.\n// Details.",
                ),
                (
                    "obligation",
                    "pub fn",
                    "/// Summary λ.\n/// # Safety\n/// Preserve this.\n#[allow(\n    unused\n)]\npub fn f() {}\n",
                    "/// # Allocations\n///\n/// Valid λ.",
                ),
            ] {
                let source = source.replace('\n', newline);
                let (_dir, mut session, mut request) = setup(&source, action, needle);
                let editor = session.open_source_editor(request.clone()).unwrap();
                assert!(!editor.can_remove);
                assert_eq!(fs::read_to_string(&editor.destination).unwrap(), source);
                assert!(
                    session
                        .commit_source_editor(&editor.token, Some(editor.document.clone()))
                        .is_err()
                );
                let result = session
                    .commit_source_editor(&editor.token, Some(document.into()))
                    .unwrap();
                let mut applied = source.clone();
                applied.replace_range(result.edit.start..result.edit.end, &result.edit.text);
                assert_eq!(applied, result.buffer.content);
                let buffer = result.buffer;
                assert!(session.analysis.stale);
                assert_eq!(buffer.content.replace(newline, "").contains('\n'), false);
                request.revision = buffer.revision;
                let editor = session.open_source_editor(request.clone()).unwrap();
                assert!(editor.can_remove);
                assert_eq!(editor.document, document);
                let updated = document.replace("Valid λ.", "Updated λ.");
                let result = session
                    .commit_source_editor(&editor.token, Some(updated.clone()))
                    .unwrap();
                let mut applied = buffer.content.clone();
                applied.replace_range(result.edit.start..result.edit.end, &result.edit.text);
                assert_eq!(applied, result.buffer.content);
                let buffer = result.buffer;
                assert_eq!(buffer.content.matches("Updated λ.").count(), 1);
                assert!(!buffer.content.contains("Valid λ."));
                request.revision = buffer.revision;
                let editor = session.open_source_editor(request.clone()).unwrap();
                assert_eq!(editor.document, updated);
                let result = session.commit_source_editor(&editor.token, None).unwrap();
                let mut applied = buffer.content.clone();
                applied.replace_range(result.edit.start..result.edit.end, &result.edit.text);
                assert_eq!(applied, result.buffer.content);
                let buffer = result.buffer;
                let expected = if action == "obligation" {
                    source.replace("#[allow(", &format!("///{newline}#[allow("))
                } else {
                    source.clone()
                };
                assert_eq!(buffer.content, expected);
                assert!(session.commit_source_editor(&editor.token, None).is_err());
            }
        }
    }

    #[test]
    fn existing_sections_and_sibling_markers_are_preserved() {
        for (action, needle, source, original, updated) in [
            (
                "justification",
                "allocate();",
                "fn f() {\n    // SAFETY: Keep.\n    // ALLOC: Old.\n    // More detail.\n    // PANIC: Keep too.\n    allocate();\n}\n",
                "// ALLOC: Old.\n// More detail.",
                "// ALLOC: New.",
            ),
            (
                "obligation",
                "pub fn",
                "/// Summary.\n/// # Allocations\n/// Old.\n/// ## Details\n/// Detail.\n/// # Examples\n/// Keep.\n#[inline]\npub fn f() {}\n",
                "/// # Allocations\n/// Old.\n/// ## Details\n/// Detail.",
                "/// # Allocations\n/// New.",
            ),
        ] {
            let (_dir, mut session, request) = setup(source, action, needle);
            let editor = session.open_source_editor(request).unwrap();
            assert_eq!(editor.document, original);
            let saved = session
                .commit_source_editor(&editor.token, Some(updated.into()))
                .unwrap()
                .buffer;
            let indent = if action == "justification" {
                "    "
            } else {
                ""
            };
            let original = original.replace('\n', &format!("\n{indent}"));
            let updated = updated.replace('\n', &format!("\n{indent}"));
            assert_eq!(saved.content, source.replace(&original, &updated));
        }
    }

    #[test]
    fn unsafe_block_and_literals_use_lexical_attachments() {
        let source =
            "const S: &str = r#\"\n// ALLOC: fake\n\"#;\nfn f() {\n    unsafe { allocate(); }\n}\n";
        let (_dir, mut session, request) = setup(source, "justification", "allocate();");
        let editor = session.open_source_editor(request).unwrap();
        let saved = session
            .commit_source_editor(&editor.token, Some("// ALLOC: Valid.".into()))
            .unwrap()
            .buffer;
        assert_eq!(
            saved.content,
            source.replace("    unsafe", "    // ALLOC: Valid.\n    unsafe")
        );
    }

    #[test]
    fn conflicts_and_invalid_documents_leave_source_and_draft_untouched() {
        for conflict in ["disk", "revision", "generation", "running", "token"] {
            let source = "fn f() {\n    allocate();\n}\n";
            let (_dir, mut session, request) = setup(source, "justification", "allocate();");
            let editor = session.open_source_editor(request).unwrap();
            for bad in [
                "// OTHER: text",
                "// ALLOC: text\nallocate();",
                "// ALLOC: text\n/// # Bad",
                "// ALLOC: text\n// OTHER: text",
            ] {
                assert!(
                    session
                        .commit_source_editor(&editor.token, Some(bad.into()))
                        .is_err(),
                    "{bad}"
                );
            }
            let mut token = editor.token.clone();
            match conflict {
                "disk" => fs::write(&editor.destination, format!("// external\n{source}")).unwrap(),
                "revision" => {
                    session
                        .save_source(
                            &editor.destination,
                            editor.target.revision,
                            format!("// saved\n{source}"),
                        )
                        .unwrap();
                }
                "generation" => session.analysis.generation += 1,
                "running" => session.analysis.running = true,
                _ => token.push('!'),
            }
            let before = fs::read_to_string(&editor.destination).unwrap();
            assert!(
                session
                    .commit_source_editor(&token, Some("// ALLOC: Valid.".into()))
                    .is_err(),
                "{conflict}"
            );
            assert_eq!(fs::read_to_string(&editor.destination).unwrap(), before);
            assert!(session.pending_source_editor.is_some());
        }
    }

    #[test]
    fn bare_markers_blank_lines_and_expired_editors_remain_safe() {
        let source = "fn f() {\n    // ALLOC\n    allocate();\n}\n";
        let (_dir, mut session, mut request) = setup(source, "justification", "allocate();");
        let editor = session.open_source_editor(request.clone()).unwrap();
        assert_eq!(editor.document, "// ALLOC:");
        let next = session.open_source_editor(request.clone()).unwrap();
        assert!(
            session
                .commit_source_editor(&editor.token, Some("// ALLOC: Valid.".into()))
                .is_err()
        );
        let buffer = session
            .commit_source_editor(&next.token, Some("// ALLOC: Valid.\n\n// Details.".into()))
            .unwrap()
            .buffer;
        assert!(
            buffer
                .content
                .contains("    // ALLOC: Valid.\n    //\n    // Details.\n")
        );
        request.revision = buffer.revision;
        let editor = session.open_source_editor(request).unwrap();
        assert_eq!(editor.document, "// ALLOC: Valid.\n//\n// Details.");
        let buffer = session
            .commit_source_editor(&editor.token, None)
            .unwrap()
            .buffer;
        assert_eq!(buffer.content, source.replace("    // ALLOC\n", ""));
    }

    #[test]
    fn duplicate_sections_and_shared_line_syntax_are_rejected() {
        for source in [
            "fn f() { allocate(); }",
            "fn f() {\n    // ALLOC: One.\n    // ALLOC: Two.\n    allocate();\n}\n",
        ] {
            let (_dir, mut session, request) = setup(source, "justification", "allocate();");
            assert!(session.open_source_editor(request).is_err());
        }
    }
}
