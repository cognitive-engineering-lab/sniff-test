//! GUI-generated files must be usable by a new analyzer session.
#[allow(dead_code)]
mod common;

use sniff_test_audit_bridge::{AnalysisConfig, Session};
use std::fs;
use std::process::Command;

fn analyze(session: &mut Session) {
    let config = session.begin_analysis().unwrap();
    let mut command = Command::new(&config.executable);
    command
        .args(&config.arguments)
        .current_dir(&config.directory);
    common::clean_cargo_package_env(&mut command);
    session.finish_analysis(Ok(command.output().unwrap()));
    assert_eq!(
        session.analysis.status, "complete",
        "{}",
        session.analysis.log
    );
}

#[test]
fn gui_source_selectors_survive_fresh_analysis() {
    let _lock = common::lock_nested_cargo();
    for (action, operations) in [
        ("justification", "    assert!(flag); assert!(other);\r\n"),
        (
            "justification",
            "    assert!(\r\n        flag,\r\n        \"λ\"\r\n    );\r\n",
        ),
        (
            "justification",
            "    let _ = 100 /\r\n        (flag as u32);\r\n",
        ),
        ("justification", "    check!(flag);\r\n"),
        ("obligation", "    assert!(flag);\r\n"),
    ] {
        let root = tempfile::tempdir().unwrap();
        let dep = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("src")).unwrap();
        fs::create_dir(dep.path().join("src")).unwrap();
        fs::write(dep.path().join("Cargo.toml"), "[package]\nname='hyphen-package'\nversion='1.2.3'\nedition='2024'\n[lib]\nname='actual_crate'\n").unwrap();
        let source = format!(
            "// λ\r\nmacro_rules! check {{ ($v:expr) => {{ assert!($v) }}; }}\r\n/// Summary.\r\n/// # Safety\r\n/// Preserve this other contract.\r\n#[inline]\r\nfn risky(flag: bool, other: bool) {{\r\n{operations}}}\r\npub fn bridge(flag: bool, other: bool) {{ risky(flag, other); }}\r\n"
        );
        let path = dep.path().join("src/lib.rs");
        fs::write(&path, &source).unwrap();
        fs::write(root.path().join("Cargo.toml"), format!("[package]\nname='gui-override-consumer'\nversion='0.1.0'\nedition='2024'\n[workspace]\n[dependencies]\nhyphen-package={{path={:?}}}\n", dep.path())).unwrap();
        fs::copy(
            common::repo_root().join("rust-toolchain.toml"),
            root.path().join("rust-toolchain.toml"),
        )
        .unwrap();
        fs::write(
            root.path().join("src/lib.rs"),
            "pub fn entry(flag: bool, other: bool) { actual_crate::bridge(flag, other); }\n",
        )
        .unwrap();
        fs::write(
            root.path().join("sniff-test.toml"),
            "[contracts]\noverride-files=['existing.toml']\n",
        )
        .unwrap();
        fs::write(root.path().join("existing.toml"), "# Keep comment\n[overrides.crates.actual_crate.\"9.9.9\"]\n\"src/lib.rs:6:6\" = \"# Panics\\nInactive version\"\n").unwrap();
        let config = AnalysisConfig {
            executable: env!("CARGO_BIN_EXE_cargo-sniff-test").into(),
            directory: root.path().into(),
            arguments: vec![
                "-e".into(),
                "panic".into(),
                "--message-format=json".into(),
                "--color=never".into(),
            ],
        };
        let mut session = Session::open(
            root.path().into(),
            root.path().join("target"),
            config.clone(),
        )
        .unwrap();
        analyze(&mut session);
        let mut targets = Vec::new();
        for finding in &session.analysis.findings {
            if !finding.dependency {
                continue;
            }
            for target in finding
                .audit
                .as_ref()
                .unwrap()
                .targets
                .iter()
                .filter(|t| t.action == action)
            {
                if let Some(selector) = &target.selector {
                    if !targets.iter().any(
                        |(_, s): &(String, sniff_test_report::OverrideSelector)| {
                            s.same_target(selector)
                        },
                    ) {
                        targets.push((finding.id.clone(), selector.clone()));
                    }
                }
            }
        }
        assert!(
            !targets.is_empty(),
            "no {action} targets: {:?}",
            session.analysis.findings
        );
        if operations.contains("assert!(other)") {
            assert_eq!(targets.len(), 2);
        }
        let path = path.canonicalize().unwrap().to_string_lossy().into_owned();
        for (id, selector) in &targets {
            assert_eq!(selector.crate_name, "actual_crate");
            assert_eq!(selector.version, "1.2.3");
            assert_eq!(selector.source_path, "src/lib.rs");
            assert_eq!(selector.line, if action == "obligation" { 7 } else { 8 });
            let buffer = session.buffer(&path).unwrap();
            let document = if action == "obligation" {
                "/// # Panics\n/// Caller must check the flag."
            } else {
                "// PANIC: caller checked the flag."
            };
            session
                .save_override(id, action, buffer.revision, document.into())
                .unwrap();
        }
        let buffer = session.buffer(&path).unwrap();
        let plan = session
            .prepare_override_apply(&path, buffer.revision, None)
            .unwrap();
        session.apply_overrides(&plan.token, true).unwrap();
        if action == "justification" {
            for reason in ["revised", "revised again"] {
                let buffer = session.buffer(&path).unwrap();
                let buffer = session
                    .edit_override(&path, buffer.revision, 0, format!("// PANIC: {reason}"))
                    .unwrap();
                let plan = session
                    .prepare_override_apply(&path, buffer.revision, None)
                    .unwrap();
                session.apply_overrides(&plan.token, true).unwrap();
            }
        }
        let saved = fs::read_to_string(root.path().join("existing.toml")).unwrap();
        assert!(saved.contains("# Keep comment"));
        assert!(saved.contains("9.9.9"));
        assert!(saved.contains("1.2.3"));
        assert!(!saved.contains("[[annotations]]"));
        if action == "obligation" {
            assert!(saved.contains("Preserve this other contract."));
        } else {
            assert_eq!(saved.matches("PANIC:").count(), targets.len());
            assert!(!saved.contains("PANIC: revised\\n"));
        }
        assert_eq!(fs::read_to_string(&path).unwrap(), source);
        drop(session);
        let mut fresh =
            Session::open(root.path().into(), root.path().join("target"), config).unwrap();
        analyze(&mut fresh);
        if action == "justification" {
            assert!(
                fresh.analysis.findings.is_empty(),
                "{:?}",
                fresh.analysis.findings
            );
        } else {
            assert!(
                fresh
                    .analysis
                    .findings
                    .iter()
                    .all(|f| f.class.as_deref() == Some("documented-obligation")),
                "{:?}",
                fresh.analysis.findings
            );
            assert!(
                fresh
                    .analysis
                    .findings
                    .iter()
                    .any(|f| f.class.as_deref() == Some("documented-obligation")),
                "{:?}",
                fresh.analysis.findings
            );
        }
    }
}
