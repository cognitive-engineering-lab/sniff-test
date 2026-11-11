use super::*;

fn setup(source: &str) -> (tempfile::TempDir, Session, String) {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("lib.rs");
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
    let path = path.to_string_lossy().into_owned();
    let buffer = session.buffer(&path).unwrap();
    let path = buffer.path.clone();
    let location = |start, len| Location {
        path: path.clone(),
        source_id: "source".into(),
        start,
        end: start + len,
        available: true,
        hash: buffer.hash.clone(),
    };
    let site = location(source.rfind("danger();").unwrap(), 9);
    let function = location(source.find("pub fn work").unwrap(), 11);
    let audit = AuditMetadata {
        effect: "panic".into(),
        obligation: "Panics".into(),
        justification: "PANIC".into(),
        source: Some(site.clone()),
        root: Some(function.clone()),
        contract: None,
        obligation_documentation: None,
        trace: vec![],
        targets: vec![
            EditTarget {
                selector: None,
                action: "justification".into(),
                location: site,
            },
            EditTarget {
                selector: None,
                action: "obligation".into(),
                location: function,
            },
        ],
    };
    let finding = Finding {
        direct_source: None,
        id: "one".into(),
        crate_name: "test".into(),
        effect: Some("panic".into()),
        kind: "effect".into(),
        class: Some("concrete-invocation".into()),
        level: "warn".into(),
        root: Some("work".into()),
        trace_id: None,
        reason: "test".into(),
        requirements: vec![],
        missing_requirements: vec![],
        display_trace: vec![],
        audit: Some(audit),
        dependency: false,
    };
    let mut shared = finding.clone();
    shared.id = "shared".into();
    let mut other = finding.clone();
    other.id = "other-effect".into();
    other.effect = Some("safety".into());
    let audit = other.audit.as_mut().unwrap();
    audit.effect = "safety".into();
    audit.obligation = "Safety".into();
    audit.justification = "SAFETY".into();
    session.analysis.findings = vec![finding, shared, other];
    (root, session, path)
}

#[test]
fn successful_source_saves_update_shared_traces_and_remove_deleted_progress() {
    let original = "pub fn work() {\n    danger();\n}\n";
    let (_root, mut session, path) = setup(original);
    session.refresh_audit_progress();
    assert_eq!(session.audit_progress("one"), AuditProgress::default());
    let revision = session.analysis.audit_revision;
    let buffer = session.buffer(&path).unwrap();
    session
        .prepare_template("one", "justification", buffer.revision)
        .unwrap();
    session.refresh_audit_progress();
    assert_eq!(session.analysis.audit_revision, revision);
    let saved = "/// # Panics\n/// Caller handles errors.\n#[inline]\npub fn work() {\n    // PANIC: inputs checked\n    danger();\n}\n";
    let buffer = session
        .save_source(&path, buffer.revision, saved.into())
        .unwrap();
    session.refresh_audit_progress();
    for id in ["one", "shared"] {
        assert_eq!(
            session.audit_progress(id),
            AuditProgress {
                justified: true,
                propagated: true
            }
        );
    }
    assert_eq!(
        session.audit_progress("other-effect"),
        AuditProgress::default()
    );
    assert!(session.analysis.audit_revision > revision);
    assert!(
        session
            .save_source(&path, buffer.revision - 1, original.into())
            .is_err()
    );
    session.refresh_audit_progress();
    assert!(session.audit_progress("one").justified);
    session
        .save_source(&path, buffer.revision, original.into())
        .unwrap();
    session.refresh_audit_progress();
    assert_eq!(session.audit_progress("one"), AuditProgress::default());
}

#[test]
fn blank_sections_other_effects_and_comment_like_literals_do_not_count() {
    for source in [
        "/// # Panics\n///\npub fn work() {\n // PANIC:\n danger();\n}\n",
        "/// # Panics\n///\n/// # Safety\n/// Other contract.\npub fn work() {\n // PANIC:\n // SAFETY: different effect\n danger();\n}\n",
        "pub fn work() {\n let _ = r#\"\n // PANIC: fake\n danger();\n \"#;\n}\n",
        "pub fn work() {\n /* nested /* comment */\n // PANIC: fake\n danger();\n */\n}\n",
    ] {
        let (_root, mut session, _path) = setup(source);
        session.refresh_audit_progress();
        assert_eq!(
            session.audit_progress("one"),
            AuditProgress::default(),
            "{source}"
        );
    }
}

#[test]
fn lexical_attachment_handles_unicode_crlf_and_multiline_explanations() {
    let source = "// λ\r\n/// # Panics\r\n/// Caller handles it.\r\n#[allow(\r\n unused\r\n)]\r\npub fn work() {\r\n // PANIC:\r\n // The invariant holds.\r\n danger();\r\n}\r\n";
    let (_root, mut session, path) = setup(source);
    session.refresh_audit_progress();
    assert_eq!(
        session.audit_progress("one"),
        AuditProgress {
            justified: true,
            propagated: true
        }
    );
    fs::write(path, source.replace("The invariant holds.", "")).unwrap();
    session.refresh_audit_progress();
    assert_eq!(session.audit_progress("one"), AuditProgress::default());
}
