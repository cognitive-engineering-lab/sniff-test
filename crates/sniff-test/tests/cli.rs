mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::{
    CommandOutput, assert_public_output_uses_human_words, clean_cargo_package_env,
    copy_fixture_dir, extract_group_handle, extract_group_handles, lock_nested_cargo,
    normalize_line, render_snapshot, repo_root, rustc_sysroot,
};

struct Case {
    denied: bool,
    app_crate: bool,
    color: &'static str,
    working_dir: Option<&'static str>,
    config_append: &'static str,
    args: &'static [&'static str],
    rustflags: Option<&'static str>,
}

#[test]
fn full_stack_trace_footer_uses_rustc_note_color_without_a_trailing_blank_line() {
    const HINT: &str = "set `show-full-stack-trace = true` under `[analysis]` in sniff-test.toml to show every reachability step";

    let repo = repo_root();
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_cargo-sniff-test"));
    let case = Case::new().in_app().color("always");
    let (output, _, _temp) = run_case(
        &repo,
        &binary,
        "full_stack_trace_footer_color",
        "dependency_obligation",
        &case,
    );

    assert_eq!(output.status.code(), Some(0), "stderr:\n{}", output.stderr);
    let hint_line = output
        .stderr
        .lines()
        .find(|line| line.contains(HINT))
        .expect("full-stack-trace hint should be emitted");
    assert!(
        hint_line.contains("\u{1b}[92mnote\u{1b}[0m"),
        "the note label should use rustc's green diagnostic style:\n{}",
        output.stderr,
    );
    let (_, after_hint) = output
        .stderr
        .split_once(HINT)
        .expect("full-stack-trace hint should be emitted");
    assert!(
        after_hint.starts_with('\n') && !after_hint.starts_with("\n\n"),
        "the Cargo warning footer should follow without a blank line:\n{}",
        output.stderr,
    );
}

macro_rules! cli_cases {
    ($($fixture:literal => { $($case:ident => $spec:expr;)+ })+) => {
        $(
            $(
                #[test]
                fn $case() {
                    run_named_case(stringify!($case), $fixture, &$spec);
                }
            )+
        )+
    };
}

cli_cases! {
    "direct_panic" => {
        panic_invocation_can_be_allowed => Case::new()
            .config_append("\n[panics.lints]\npanic-invocation = \"allow\"\n");
    }
    "source_aggregation" => {
        source_aggregation_emits_one_diagnostic_per_root => Case::new()
            .denied();
        source_aggregation_emits_one_warning_per_root => Case::new()
            .config_append("\n[panics.lints]\npanic-invocation = \"warn\"\n");
    }
    "safe_markers" => {
        full_stack_trace => Case::new()
            .denied()
            .config_append("\n[analysis]\nshow-full-stack-trace = true\n");
    }
    "closure_call_graph" => {
        closure_call_graph_diagnostics => Case::new()
            .args(&["--manifest", "basic.toml"])
            .denied();
    }
    "panic_axioms" => {
        compiler_assert_division_override_uses_umbrella_fallback =>
            Case::new()
                .config_append(
                    "\n[panics.lints]\n\
                     compiler-assert-division-by-zero = \"deny\"\n\
                     compiler-assert = \"allow\"\n\
                     panic-invocation = \"allow\"\n",
                )
                .denied();
        compiler_assert_overrides_are_independent =>
            Case::new()
                .config_append(
                    "\n[panics.lints]\n\
                     compiler-assert = \"allow\"\n\
                     compiler-assert-remainder-by-zero = \"warn\"\n\
                     compiler-assert-bounds-check = \"deny\"\n\
                     panic-invocation = \"allow\"\n",
                )
                .denied();
        cargo_manifest_path_forwarding => Case::new()
            .working_dir("..")
            .args(&["--", "--manifest-path", "panic_axioms/Cargo.toml"])
            .denied();
    }
    "report_roots" => {
        missing_report_root_diagnostic => Case::new()
            .args(&["--manifest", "deny-missing.toml"])
            .denied();
        empty_report_roots_diagnostic => Case::new()
            .args(&["--manifest", "empty.toml"]);
    }
    "unsafe_ops" => {
        unsafe_op_missing_justification_can_be_denied => Case::new()
            .config_append("\n[safety.lints]\nunsafe-op-missing-justification = \"deny\"\n")
            .denied();
        unsafe_op_overrides_use_umbrella_fallback =>
            Case::new()
                .config_append(
                    "\n[safety.lints]\n\
                     raw-pointer-dereference-missing-justification = \"warn\"\n\
                     unsafe-op-missing-justification = \"allow\"\n\
                     inline-assembly-missing-justification = \"deny\"\n",
                )
                .denied();
    }
}

#[test]
fn effect_flag_tracks_only_selected_domain() {
    let repo = repo_root();
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_cargo-sniff-test"));

    for (name, effect, args, included, excluded) in [
        (
            "effect_flag_selects_safety",
            "safety",
            &["--effect", "safety"][..],
            "sniff-test::safety",
            "sniff-test::panics",
        ),
        (
            "effect_flag_selects_panic",
            "panic",
            &["--effect", "panic"][..],
            "sniff-test::panics",
            "sniff-test::safety",
        ),
    ] {
        for fixture in ["effect_marker_paths", "macro_contracts"] {
            let case = Case::new().args(args).denied();
            let (output, _, _temp) = run_case(&repo, &binary, name, fixture, &case);
            assert_eq!(
                output.status.code(),
                Some(101),
                "stderr:\n{}",
                output.stderr
            );
            assert!(
                output.stderr.contains(included),
                "selected `{effect}` diagnostics were absent:\n{}",
                output.stderr,
            );
            assert!(
                !output.stderr.contains(excluded),
                "deselected diagnostics were emitted for `{effect}`:\n{}",
                output.stderr,
            );
        }
    }
}

#[test]
fn unsafe_precondition_helpers_do_not_export_panic_contracts() {
    let repo = repo_root();
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_cargo-sniff-test"));
    let (output, _, _temp) = run_case(
        &repo,
        &binary,
        "unsafe_precondition_helpers_do_not_export_panic_contracts",
        "assert_unsafe_precondition",
        &Case::new(),
    );

    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout:\n{}\nstderr:\n{}",
        output.stdout,
        output.stderr
    );
    assert!(
        !output.stderr.contains("sniff-test::panics"),
        "the standard library's unsafe-precondition implementation leaked a panic finding:\n{}",
        output.stderr
    );
    assert!(
        output
            .stderr
            .contains("sniff-test::safety::unsafe-call-missing-requirements"),
        "the caller's independent unsafe obligation must remain audited:\n{}",
        output.stderr
    );
}

#[test]
fn config_found_from_subdirectory() {
    let repo = repo_root();
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_cargo-sniff-test"));
    let case = Case::new().working_dir("src").denied();
    let (output, _, _temp) = run_case(
        &repo,
        &binary,
        "config_found_from_subdirectory",
        "panic_axioms",
        &case,
    );

    assert_eq!(
        output.status.code(),
        Some(101),
        "stderr:\n{}",
        output.stderr
    );
    assert_panic_axiom_lint_codes(&output.stderr);
    assert!(
        !output.stderr.contains("no sniff-test.toml found"),
        "the manifest should be discovered from the fixture root:\n{}",
        output.stderr
    );
}

#[test]
fn rustflags_env_does_not_disable_analysis() {
    let repo = repo_root();
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_cargo-sniff-test"));
    let case = Case::new()
        .rustflags("--cfg sniff_test_cli_user_flag")
        .denied();
    let (output, _, _temp) = run_case(
        &repo,
        &binary,
        "rustflags_env_does_not_disable_analysis",
        "panic_axioms",
        &case,
    );

    assert_eq!(
        output.status.code(),
        Some(101),
        "stderr:\n{}",
        output.stderr
    );
    assert_panic_axiom_lint_codes(&output.stderr);
}

#[test]
fn every_cargo_run_emits_the_workspace_report() {
    let name = "every_cargo_run_emits_the_workspace_report";
    let fixture = repo_root().join("tests/fixtures/panic_requirements");
    let temp = tempfile::Builder::new()
        .prefix("sniff-test-cli-repeat-report-")
        .tempdir()
        .expect("create temporary fixture directory");
    let root = temp.path().join("panic_requirements");
    copy_fixture_dir(&fixture, &root).expect("copy panic requirements fixture");

    let binary = PathBuf::from(env!("CARGO_BIN_EXE_cargo-sniff-test"));
    let case = Case::new().args(&["--message-format", "json"]);
    let run = || run_cargo_sniff_test(&binary, &root, name, &case);
    let _cargo_guard = lock_nested_cargo();
    let first = run();
    let second = run();

    for (run_name, output) in [("first", first), ("second", second)] {
        assert!(
            output.status.success(),
            "{run_name} run failed\nstdout:\n{}\nstderr:\n{}",
            output.stdout,
            output.stderr
        );
        let report_count = output
            .stdout
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|message| message["reason"] == "sniff-test-artifact")
            .count();
        assert_eq!(
            report_count, 1,
            "{run_name} run should emit exactly one workspace report\nstdout:\n{}",
            output.stdout
        );
    }
}

#[cfg(unix)]
#[test]
fn compact_diagnostic_group_can_be_explained_from_the_explanation_report() {
    let fixture = repo_root().join("tests/fixtures/direct_panic");
    let temp = tempfile::tempdir().expect("create temporary fixture directory");
    let root = temp.path().join("direct_panic");
    copy_fixture_dir(&fixture, &root).expect("copy direct panic fixture");
    let source = "fn direct_panic() {\n    panic!(\"not documented\");\n}\n\npub fn entry_point() {\n    direct_panic();\n}\n";
    fs::write(root.join("src/lib.rs"), source)
        .expect("write fixture source with an actionable invocation");
    fs::write(
        root.join("sniff-test.toml"),
        "[analysis]\nreport-roots = [\"direct_panic::entry_point\"]\n\n[panics]\npanic-sink-namespaces = [\n    \"core::panicking::**\",\n    \"std::panicking::**\",\n    \"core::std::rt::panic_fmt\",\n    \"std::rt::panic_fmt\",\n]\n",
    )
    .expect("write fixture manifest");
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_cargo-sniff-test"));
    let cache_dir = temp.path().join("cache");
    let run_analysis = || {
        let mut command = Command::new(&binary);
        clean_cargo_package_env(&mut command);
        let output = command
            .args(["--cache-dir"])
            .arg(&cache_dir)
            .args(["--color", "never"])
            .current_dir(&root)
            .output()
            .expect("run compact cargo diagnostic");
        CommandOutput::from_output(output)
    };

    let _cargo_guard = lock_nested_cargo();
    let first = run_analysis();
    assert_eq!(first.status.code(), Some(101), "stderr:\n{}", first.stderr);
    for expected in [
        "this panic is not accounted for on every path",
        "src/lib.rs:2",
        "src/lib.rs:6",
        "account for this path at this call",
    ] {
        assert!(
            first.stderr.contains(expected),
            "the compact diagnostic must retain `{expected}`:\n{}",
            first.stderr
        );
    }
    let full_detail = "no `// PANIC:` justification was found for this source";
    assert!(
        !first.stderr.contains(full_detail),
        "full trace detail should not be printed inline:\n{}",
        first.stderr
    );

    let first_handle = extract_group_handle(&first.stderr);
    let frontend = fs::canonicalize(&binary).expect("canonical frontend executable");
    let advertised_explain = format!(
        "'{}' explain {first_handle} --cache-dir '{}'",
        frontend.display(),
        cache_dir.display()
    );
    assert_eq!(
        extract_explain_command(&first.stderr),
        advertised_explain,
        "the diagnostic must identify the frontend binary and explanation store"
    );

    let mut explain = Command::new("sh");
    clean_cargo_package_env(&mut explain);
    let explained = explain
        .env_remove("NO_COLOR")
        .env_remove("CLICOLOR_FORCE")
        .env_remove("FORCE_COLOR")
        .args(["-c", &advertised_explain])
        .current_dir(&root)
        .output()
        .expect("execute the advertised explanation command exactly");
    assert_success(&explained, "execute the advertised explanation command");
    let explanation = String::from_utf8(explained.stdout).expect("explanation should be utf-8");
    assert_native_explanation(
        &binary,
        &root,
        &cache_dir,
        &first_handle,
        &explanation,
        full_detail,
    );

    fs::write(
        root.join("src/lib.rs"),
        format!("// An unrelated edit must not rename the panic below.\n{source}"),
    )
    .expect("make an unrelated source edit before the recorded diagnostic");

    let second = run_analysis();
    assert_eq!(
        second.status.code(),
        Some(101),
        "stderr:\n{}",
        second.stderr
    );
    assert_eq!(
        extract_group_handle(&second.stderr),
        first_handle,
        "an unchanged diagnostic group must keep its handle after unrelated source edits"
    );
}

#[cfg(unix)]
fn assert_native_explanation(
    binary: &Path,
    root: &Path,
    cache_dir: &Path,
    handle: &str,
    explanation: &str,
    reason: &str,
) {
    for expected in [
        handle,
        reason,
        "report root -> effect source",
        "direct_panic::entry_point --direct-call-> direct_panic::direct_panic",
        "panic!(\"not documented\");",
        "^^",
    ] {
        assert!(
            explanation.contains(expected),
            "the explain command must restore `{expected}`:\n{explanation}"
        );
    }
    assert!(
        explanation.starts_with("error:"),
        "explain must retain the native diagnostic heading:\n{explanation}"
    );
    assert!(
        !explanation.contains('\x1b'),
        "default explain output must remain plain when piped: {explanation:?}"
    );
    let cached_explanations =
        fs::read_to_string(cache_dir.join("explain.json")).expect("read the recorded explanations");
    let cached_report: serde_json::Value =
        serde_json::from_str(&cached_explanations).expect("explanation report should be JSON");
    let cached_diagnostic = cached_report["diagnostics"][0]["explanation"]
        .as_str()
        .expect("the report should contain the recorded diagnostic");
    assert!(
        cached_diagnostic.contains("\x1b["),
        "native colors must be recorded even when analysis uses --color never"
    );
    for color in ["auto", "never", "always"] {
        let mut command = Command::new(binary);
        command
            .env_remove("NO_COLOR")
            .env_remove("CLICOLOR_FORCE")
            .env_remove("FORCE_COLOR");
        if color == "always" {
            command.env("NO_COLOR", "1");
        }
        let colored = command
            .args(["explain", handle, "--color", color, "--cache-dir"])
            .arg(cache_dir)
            .current_dir(root)
            .output()
            .expect("explain the recorded diagnostic with an explicit color mode");
        assert_success(&colored, &format!("explain --color {color}"));
        let colored = String::from_utf8(colored.stdout).expect("explanation should be utf-8");
        if color != "always" {
            assert_eq!(
                colored, explanation,
                "piped --color {color} must stay plain"
            );
            continue;
        }
        assert_eq!(
            colored, cached_diagnostic,
            "forced-color explain must replay the cached native diagnostic exactly"
        );
        for line in [
            colored.lines().next().expect("explanation title"),
            colored
                .lines()
                .find(|line| line.contains(reason))
                .expect("explanation reason"),
        ] {
            assert!(
                line.contains("\x1b["),
                "forced color must style the title and reason: {line:?}"
            );
        }
        let mut segments = colored.split("\x1b[");
        let mut plain = segments.next().unwrap_or_default().to_owned();
        for segment in segments {
            let (parameters, text) = segment.split_once('m').expect("complete ANSI style");
            assert!(
                parameters
                    .chars()
                    .all(|character| character.is_ascii_digit() || character == ';'),
                "explain must only emit ANSI text styles: {parameters:?}"
            );
            plain.push_str(text);
        }
        assert_eq!(
            plain, explanation,
            "color must preserve the explanation text"
        );
    }
    assert_eq!(
        fs::read_to_string(cache_dir.join("explain.json")).expect("reread explanations"),
        cached_explanations,
        "rendering color must not rewrite the cached explanations"
    );
}

#[cfg(unix)]
#[test]
fn source_contract_overrides_survive_compact_diagnostics_and_explanations() {
    let temp = tempfile::tempdir().expect("create temporary fixture directory");
    let root = temp.path().join("source_contract_overrides");
    copy_fixture_dir(
        &repo_root().join("tests/fixtures/source_contract_overrides"),
        &root,
    )
    .expect("copy source contract override fixture");
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_cargo-sniff-test"));
    let cache_dir = temp.path().join("cache");
    let mut command = Command::new(&binary);
    clean_cargo_package_env(&mut command);
    let _cargo_guard = lock_nested_cargo();
    let analyzed = command
        .arg("--cache-dir")
        .arg(&cache_dir)
        .args(["--color", "never"])
        .current_dir(&root)
        .output()
        .expect("analyze source contract overrides with compact diagnostics");
    assert_success(&analyzed, "source contract override fixture");
    let stderr = String::from_utf8(analyzed.stderr).expect("diagnostics should be utf-8");
    assert_eq!(
        stderr
            .matches("[sniff-test::panics::documented-panic]")
            .count(),
        3,
        "local, dependency, and trait source overrides must become contracts:\n{stderr}"
    );
    assert_eq!(
        stderr
            .matches("[sniff-test::panics::panic-invocation]")
            .count(),
        1,
        "the adjacent, nonselected definition must retain its direct panic:\n{stderr}"
    );
    let handles = extract_group_handles(&stderr);
    assert_eq!(handles.len(), 4, "stderr:\n{stderr}");
    let explanations = handles
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|handle| {
            let output = Command::new(&binary)
                .args(["explain", &handle, "--cache-dir"])
                .arg(&cache_dir)
                .current_dir(&root)
                .output()
                .expect("explain a source contract diagnostic group");
            assert_success(&output, "source contract explanation");
            String::from_utf8(output.stdout).expect("explanation should be utf-8")
        })
        .collect::<Vec<_>>();
    for (target, requirement) in [
        (
            "source_contract_overrides::selected_panic",
            "selected: flag must be true.",
        ),
        (
            "source_contract_dependency::dependency_panic",
            "dependency: flag must be true.",
        ),
        (
            "source_contract_overrides::trait_api::Operation::execute",
            "implemented: the implementation must satisfy its panic contract.",
        ),
    ] {
        assert!(
            !stderr.contains(requirement),
            "full requirement detail belongs in explain, not compact diagnostics:\n{stderr}"
        );
        assert!(
            explanations.iter().any(|explanation| {
                explanation.contains(target) && explanation.contains(requirement)
            }),
            "explanations must retain source-selected contract `{requirement}` on `{target}`:\n{explanations:#?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn repeated_identical_invocations_share_one_stable_diagnostic_group() {
    let fixture = repo_root().join("tests/fixtures/direct_panic");
    let temp = tempfile::Builder::new()
        .prefix("sniff-test-cli-repeated-diagnostic-groups-")
        .tempdir()
        .expect("create temporary fixture directory");
    let root = temp.path().join("direct_panic");
    copy_fixture_dir(&fixture, &root).expect("copy direct panic fixture");
    let source = "fn repeated_panics(condition: bool) {\n    if std::hint::black_box(condition) { panic!(\"x\"); }\n    if std::hint::black_box(condition) { panic!(\"x\"); }\n    if std::hint::black_box(condition) { panic!(\"x\"); }\n    if std::hint::black_box(condition) { panic!(\"x\"); }\n}\n\npub fn entry_point(condition: bool) {\n    repeated_panics(condition);\n}\n";
    fs::write(root.join("src/lib.rs"), source).expect("write repeated panic fixture source");
    fs::write(
        root.join("sniff-test.toml"),
        "[analysis]\nreport-roots = [\"direct_panic::entry_point\"]\n\n[panics]\npanic-sink-namespaces = [\n    \"core::panicking::**\",\n    \"std::panicking::**\",\n    \"core::std::rt::panic_fmt\",\n    \"std::rt::panic_fmt\",\n]\n",
    )
    .expect("write fixture manifest");

    let binary = PathBuf::from(env!("CARGO_BIN_EXE_cargo-sniff-test"));
    let cache_dir = temp.path().join("cache");
    let run_analysis = || {
        let mut command = Command::new(&binary);
        clean_cargo_package_env(&mut command);
        let output = command
            .args(["--cache-dir"])
            .arg(&cache_dir)
            .args(["--color", "never"])
            .current_dir(&root)
            .output()
            .expect("run repeated panic analysis");
        CommandOutput::from_output(output)
    };

    let _cargo_guard = lock_nested_cargo();
    let first = run_analysis();
    assert_eq!(first.status.code(), Some(101), "stderr:\n{}", first.stderr);
    let first_handles = extract_group_handles(&first.stderr);
    assert_eq!(
        first_handles.len(),
        4,
        "each invocation should emit a human finding:\n{}",
        first.stderr
    );
    assert_eq!(
        first_handles.iter().collect::<BTreeSet<_>>().len(),
        1,
        "identical invocations in one function should share one diagnostic group:\n{}",
        first.stderr
    );

    let explained = Command::new(&binary)
        .args(["explain", &first_handles[0], "--cache-dir"])
        .arg(&cache_dir)
        .current_dir(&root)
        .output()
        .expect("explain every member of the repeated-panic group");
    assert!(
        explained.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&explained.stdout),
        String::from_utf8_lossy(&explained.stderr)
    );
    let explanation = String::from_utf8(explained.stdout).expect("explanation should be utf-8");
    assert_eq!(
        explanation.matches("\n\nerror:").count(),
        3,
        "each diagnostic must be separated by a blank line:\n{explanation}"
    );
    for line in 2..=5 {
        assert!(
            explanation.contains(&format!("src/lib.rs:{line}")),
            "the group explanation must retain every invocation site:\n{explanation}"
        );
    }

    fs::write(
        root.join("src/lib.rs"),
        format!("// An unrelated edit before the function.\n{source}"),
    )
    .expect("insert unrelated source before the function");
    let second = run_analysis();
    assert_eq!(
        second.status.code(),
        Some(101),
        "stderr:\n{}",
        second.stderr
    );
    assert_eq!(
        extract_group_handles(&second.stderr)
            .into_iter()
            .collect::<BTreeSet<_>>(),
        first_handles.into_iter().collect::<BTreeSet<_>>(),
        "moving the function must not rename its diagnostic group"
    );
}

#[cfg(unix)]
#[test]
fn diagnostic_group_survives_an_unrelated_earlier_closure() {
    let fixture = repo_root().join("tests/fixtures/direct_panic");
    let temp = tempfile::Builder::new()
        .prefix("sniff-test-cli-closure-diagnostic-group-")
        .tempdir()
        .expect("create temporary fixture directory");
    let root = temp.path().join("direct_panic");
    copy_fixture_dir(&fixture, &root).expect("copy direct panic fixture");
    fs::write(
        root.join("sniff-test.toml"),
        "[analysis]\nreport-roots = [\"direct_panic::entry_point\"]\n\n[panics]\npanic-sink-namespaces = [\n    \"core::panicking::**\",\n    \"std::panicking::**\",\n    \"core::std::rt::panic_fmt\",\n    \"std::rt::panic_fmt\",\n]\n",
    )
    .expect("write fixture manifest");
    let source = "fn closure_panic() {\n    let target = || panic!(\"x\");\n    target();\n}\n\npub fn entry_point() {\n    closure_panic();\n}\n";
    fs::write(root.join("src/lib.rs"), source).expect("write closure panic fixture source");

    let binary = PathBuf::from(env!("CARGO_BIN_EXE_cargo-sniff-test"));
    let cache_dir = temp.path().join("cache");
    let run_analysis = || {
        let mut command = Command::new(&binary);
        clean_cargo_package_env(&mut command);
        let output = command
            .args(["--cache-dir"])
            .arg(&cache_dir)
            .args(["--color", "never"])
            .current_dir(&root)
            .output()
            .expect("run closure panic analysis");
        CommandOutput::from_output(output)
    };

    let _cargo_guard = lock_nested_cargo();
    let first = run_analysis();
    assert_eq!(first.status.code(), Some(101), "stderr:\n{}", first.stderr);
    let first_handle = extract_group_handle(&first.stderr);

    fs::write(
        root.join("src/lib.rs"),
        source.replacen(
            "fn closure_panic() {\n",
            "fn closure_panic() {\n    let _unrelated = || ();\n",
            1,
        ),
    )
    .expect("insert unrelated earlier closure");
    let second = run_analysis();
    assert_eq!(
        second.status.code(),
        Some(101),
        "stderr:\n{}",
        second.stderr
    );
    assert_eq!(
        extract_group_handle(&second.stderr),
        first_handle,
        "an anonymous rustc ordinal must not become part of the group scope"
    );
}

#[cfg(unix)]
#[test]
fn repeated_identical_closure_invocations_share_one_diagnostic_group() {
    let fixture = repo_root().join("tests/fixtures/direct_panic");
    let temp = tempfile::Builder::new()
        .prefix("sniff-test-cli-repeated-closure-ids-")
        .tempdir()
        .expect("create temporary fixture directory");
    let root = temp.path().join("direct_panic");
    copy_fixture_dir(&fixture, &root).expect("copy direct panic fixture");
    fs::write(
        root.join("src/lib.rs"),
        "fn repeated_closures(condition: bool) {\n    if std::hint::black_box(condition) { (|| panic!(\"x\"))(); }\n    if std::hint::black_box(condition) { (|| panic!(\"x\"))(); }\n    if std::hint::black_box(condition) { (|| panic!(\"x\"))(); }\n    if std::hint::black_box(condition) { (|| panic!(\"x\"))(); }\n}\n\npub fn entry_point(condition: bool) {\n    repeated_closures(condition);\n}\n",
    )
    .expect("write repeated closure fixture source");
    fs::write(
        root.join("sniff-test.toml"),
        "[analysis]\nreport-roots = [\"direct_panic::entry_point\"]\n\n[panics]\npanic-sink-namespaces = [\n    \"core::panicking::**\",\n    \"std::panicking::**\",\n    \"core::std::rt::panic_fmt\",\n    \"std::rt::panic_fmt\",\n]\n",
    )
    .expect("write fixture manifest");

    let binary = PathBuf::from(env!("CARGO_BIN_EXE_cargo-sniff-test"));
    let cache_dir = temp.path().join("cache");
    let mut command = Command::new(&binary);
    clean_cargo_package_env(&mut command);
    let _cargo_guard = lock_nested_cargo();
    let output = command
        .args(["--cache-dir"])
        .arg(&cache_dir)
        .args(["--color", "never"])
        .current_dir(&root)
        .output()
        .expect("run repeated closure panic analysis");
    let output = CommandOutput::from_output(output);
    assert_eq!(
        output.status.code(),
        Some(101),
        "stderr:\n{}",
        output.stderr
    );
    let handles = extract_group_handles(&output.stderr);
    assert_eq!(handles.len(), 4, "stderr:\n{}", output.stderr);
    assert_eq!(
        handles.into_iter().collect::<BTreeSet<_>>().len(),
        1,
        "anonymous bodies in one named function should share the same diagnostic group:\n{}",
        output.stderr
    );
}

fn extract_explain_command(output: &str) -> String {
    const PREFIX: &str = "run `";

    output
        .split_once(PREFIX)
        .and_then(|(_, command)| command.split_once('`'))
        .map_or_else(
            || panic!("diagnostic did not contain an explain command:\n{output}"),
            |(command, _)| command.to_owned(),
        )
}

#[test]
fn cargo_frontend_skips_build_scripts() {
    let temp = tempfile::tempdir().expect("temp dir");
    fs::create_dir(temp.path().join("src")).expect("create source directory");
    fs::write(
        temp.path().join("Cargo.toml"),
        "[package]\nname = \"build-script-scope\"\nversion = \"0.1.0\"\nedition = \"2024\"\nbuild = \"build.rs\"\n\n[workspace]\n",
    )
    .expect("write Cargo manifest");
    fs::write(
        temp.path().join("build.rs"),
        "pub fn unused_panic() { panic!(\"build helper\"); }\nfn main() {}\n",
    )
    .expect("write build script");
    fs::write(
        temp.path().join("src/lib.rs"),
        "pub fn library_target() {}\n",
    )
    .expect("write library source");

    let binary = PathBuf::from(env!("CARGO_BIN_EXE_cargo-sniff-test"));
    let mut command = Command::new(&binary);
    clean_cargo_package_env(&mut command);
    let _cargo_guard = lock_nested_cargo();
    let output = command
        .args(["--message-format", "json", "--color", "never"])
        .current_dir(temp.path())
        .output()
        .expect("run cargo frontend");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let crate_names = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|report| report["reason"] == "sniff-test-artifact")
        .filter_map(|report| report["artifact"]["crate-name"].as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    assert!(crate_names.iter().any(|name| name == "build_script_scope"));
    assert!(!crate_names.iter().any(|name| name == "build_script_build"));
}

#[test]
fn stale_source_override_for_loaded_file_without_definitions_fails_closed() {
    let temp = tempfile::tempdir().expect("temp dir");
    fs::create_dir(temp.path().join("src")).expect("create source directory");
    fs::write(
        temp.path().join("Cargo.toml"),
        "[package]\nname = \"stale-source-override\"\nversion = \"1.2.3\"\nedition = \"2024\"\n\n[workspace]\n",
    )
    .expect("write Cargo manifest");
    fs::write(temp.path().join("src/lib.rs"), "mod retired;\n").expect("write library source");
    fs::write(
        temp.path().join("src/retired.rs"),
        "pub struct FormerFunction;\n",
    )
    .expect("write loaded source without definitions");
    fs::write(
        temp.path().join("sniff-test.toml"),
        "[contracts]\noverride-files = [\"override.toml\"]\n",
    )
    .expect("write sniff-test manifest");
    fs::write(
        temp.path().join("override.toml"),
        "[overrides.crates.\"stale_source_override\".\"1.2.3\"]\n\"src/retired.rs:1:1\" = \"# Panics\\n\\n- retired: this definition must still exist.\"\n",
    )
    .expect("write stale source override");

    let binary = PathBuf::from(env!("CARGO_BIN_EXE_cargo-sniff-test"));
    let mut command = Command::new(binary);
    clean_cargo_package_env(&mut command);
    let _cargo_guard = lock_nested_cargo();
    let output = command
        .args(["--color", "never"])
        .current_dir(temp.path())
        .output()
        .expect("run cargo frontend");

    assert!(
        !output.status.success(),
        "a stale source override must fail closed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "source override `stale_source_override:1.2.3/src/retired.rs:1:1` matched no definition"
        ),
        "stderr:\n{stderr}"
    );
}

/// A compile error through the driver must exit with rustc's ordinary status,
/// not a 101 panic exit.
#[test]
fn direct_driver_compile_error_follows_rustc_exit_status() {
    let temp = tempfile::Builder::new()
        .prefix("sniff-test-cli-compile-error-")
        .tempdir()
        .expect("temp dir");
    let source = temp.path().join("broken.rs");
    fs::write(&source, "pub fn broken() -> u32 { \"text\" }\n").expect("write source");

    let driver = PathBuf::from(env!("CARGO_BIN_EXE_sniff-test-driver"));
    let mut command = Command::new(&driver);
    clean_cargo_package_env(&mut command);
    let output = command
        .args(["--message-format", "json", "--color", "never", "--"])
        .args([
            "--crate-name",
            "broken",
            "--crate-type",
            "lib",
            "--edition",
            "2024",
        ])
        .arg(&source)
        .args(["--sysroot", rustc_sysroot().as_str(), "-Zno-codegen"])
        .current_dir(temp.path())
        .output()
        .expect("run driver");

    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(
        output.status.code(),
        Some(1),
        "driver exited {:?}\nstderr:\n{stderr}",
        output.status.code()
    );
    assert!(stderr.contains("E0308"), "stderr:\n{stderr}");
    assert!(
        !stderr.contains("internal compiler error"),
        "stderr:\n{stderr}"
    );
}

#[test]
fn standalone_direct_driver_emits_a_workspace_report_with_linked_rustc_version() {
    let temp = tempfile::tempdir().expect("temp dir");
    let source = repo_root().join("tests/fixtures/direct_panic/src/lib.rs");
    let driver = PathBuf::from(env!("CARGO_BIN_EXE_sniff-test-driver"));
    let mut command = Command::new(driver);
    clean_cargo_package_env(&mut command);
    let output = command
        .args(["--message-format", "json", "--color", "never", "--"])
        .args([
            "--crate-name",
            "version_probe",
            "--crate-type",
            "lib",
            "--edition",
            "2024",
        ])
        .arg(source)
        .args(["--sysroot", rustc_sysroot().as_str(), "-Zno-codegen"])
        .env("RUSTC", "/definitely/missing/rustc")
        .current_dir(temp.path())
        .output()
        .expect("run driver");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse artifact report");
    let rustc_version = report["rustc-version"]
        .as_str()
        .expect("rustc version should be a string");
    assert_ne!(rustc_version, "rustc unknown");
    assert!(
        rustc_version.starts_with("rustc "),
        "unexpected rustc version: {rustc_version}"
    );
}

#[test]
fn direct_dependency_unit_silently_caches_complete_policy_neutral_facts() {
    let temp = tempfile::tempdir().expect("temp dir");
    let source = temp.path().join("dependency.rs");
    fs::write(
        &source,
        r#"#![allow(dead_code)]

pub fn exported() {}

fn unreachable_private_helper(values: &[u8], index: usize) -> u8 {
    values[index]
}

pub struct Probe;

impl Probe {
    pub fn associated() {}

    fn unreachable_private_associated_helper() {
        panic!("unreachable private associated helper");
    }
}

pub trait Required {
    fn bodyless(&self);
}

unsafe extern "C" {
    pub fn foreign_declaration();
}
"#,
    )
    .expect("write dependency source");
    let cache_dir = temp.path().join("cache");
    let output = run_dependency_unit(
        temp.path(),
        &cache_dir,
        "artifact_facts_dependency",
        &source,
        None,
        "json",
        &["-Zno-codegen"],
    );
    assert_silent_success(&output, "dependency unit");

    let cache_path = artifact_cache_for_crate(&cache_dir, "artifact_facts_dependency");
    let serialized = fs::read_to_string(&cache_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", cache_path.display()));
    let cache: serde_json::Value =
        serde_json::from_str(&serialized).expect("cache should contain JSON");
    assert_eq!(cache["format-version"], 29);
    assert_eq!(cache["artifact"]["crate-name"], "artifact_facts_dependency");
    assert_eq!(cache["artifact"]["scope"], "dependency");
    assert!(cache["artifact"].get("package-version").is_none());
    assert!(cache["artifact"]["id"]["stable-crate-id"].is_u64());
    assert_eq!(
        cache["artifact"]["id"]["svh"].as_str().map(str::len),
        Some(32)
    );

    let functions = cache["facts"]["functions"]
        .as_array()
        .expect("function facts should be an array");
    let display_paths = functions
        .iter()
        .map(|function| {
            function["display-path"]
                .as_str()
                .expect("function display path should be a string")
        })
        .collect::<Vec<_>>();
    for expected_name in [
        "exported",
        "unreachable_private_helper",
        "associated",
        "unreachable_private_associated_helper",
    ] {
        assert!(
            display_paths
                .iter()
                .any(|path| path.rsplit("::").next() == Some(expected_name)),
            "permanent facts omitted {expected_name}; cached paths: {display_paths:#?}"
        );
    }
    assert!(
        functions.iter().any(|function| {
            function["display-path"]
                .as_str()
                .is_some_and(|path| path.ends_with("::unreachable_private_helper"))
        }),
        "permanent facts omitted the private helper"
    );

    assert_cached_declaration_sources(&cache, functions);
    assert!(cache["facts"].get("tables").is_none());
    assert!(functions.iter().any(|function| {
        function["effects"].as_array().is_some_and(|effects| {
            effects
                .iter()
                .any(|effect| effect["kind"]["effect"] == "compiler-assert")
        })
    }));

    assert_policy_neutral_facts(&cache["facts"]);
}

#[test]
fn direct_driver_ignores_ambient_cargo_package_provenance() {
    let temp = tempfile::tempdir().expect("temp dir");
    let source = temp.path().join("ambient.rs");
    fs::write(&source, "pub fn exported() { panic!(\"ambient\"); }\n")
        .expect("write direct-driver source");
    let cache_dir = temp.path().join("cache");
    let mut command = direct_driver_command();
    let output = command
        .arg("--dependency")
        .args(["--cache-dir"])
        .arg(&cache_dir)
        .args(["--message-format", "json", "--color", "never", "--"])
        .args([
            "--crate-name",
            "ambient_provenance",
            "--crate-type",
            "rlib",
            "--edition",
            "2024",
        ])
        .arg(&source)
        .args(["--sysroot", rustc_sysroot().as_str(), "-Zno-codegen"])
        .env("CARGO_MANIFEST_DIR", temp.path())
        .env("CARGO_PKG_NAME", "unrelated-ambient-package")
        .env("CARGO_PKG_VERSION", "9.9.9")
        .current_dir(temp.path())
        .output()
        .expect("run direct dependency unit with ambient Cargo metadata");
    assert_silent_success(&output, "direct dependency unit");

    let cache_path = artifact_cache_for_crate(&cache_dir, "ambient_provenance");
    let cache: serde_json::Value = serde_json::from_slice(
        &fs::read(&cache_path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", cache_path.display())),
    )
    .expect("cache should contain JSON");
    assert!(
        cache["artifact"].get("package-name").is_none(),
        "standalone analysis must not trust an ambient Cargo package name: {cache:#}"
    );
    assert!(
        cache["artifact"].get("package-version").is_none(),
        "standalone analysis must not trust an ambient Cargo package version: {cache:#}"
    );
    let sources = cache["facts"]["source-files"]
        .as_array()
        .expect("source files should be an array");
    assert!(
        sources
            .iter()
            .all(|source| source.get("logical-path").is_none()),
        "standalone analysis must not derive package-relative paths from ambient Cargo metadata: {sources:#?}"
    );

    let manifest = temp.path().join("sniff-test.toml");
    fs::write(
        &manifest,
        "[panics]\npanic-sink-namespaces = [\"core::panicking::**\"]\n",
    )
    .expect("write workspace analysis manifest");
    let output = run_workspace_unit(
        temp.path(),
        &cache_dir,
        &manifest,
        "ambient_provenance",
        &source,
        "json",
        |command| {
            command
                .env("CARGO_MANIFEST_DIR", temp.path())
                .env("CARGO_PKG_NAME", "unrelated-ambient-package")
                .env("CARGO_PKG_VERSION", "9.9.9");
        },
    );
    assert_success(
        &output,
        "standalone workspace unit with ambient Cargo metadata",
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("standalone workspace report");
    let finding = report["findings"]
        .as_array()
        .expect("workspace findings")
        .iter()
        .find(|finding| finding["kind"] == "panic-invocation")
        .expect("the workspace panic must produce a finding");
    assert_eq!(finding["owner"]["crate"], "ambient_provenance");
    for field in ["package-name", "package-version"] {
        assert!(
            finding["owner"].get(field).is_none(),
            "standalone finding ownership must not trust ambient Cargo {field}: {finding:#}"
        );
    }
}

fn assert_cached_declaration_sources(cache: &serde_json::Value, functions: &[serde_json::Value]) {
    let definitions = cache["facts"]["definitions"]
        .as_array()
        .expect("definition source facts should be an array");
    for expected_name in ["bodyless", "foreign_declaration"] {
        let definition = definitions
            .iter()
            .find(|definition| {
                definition["display-path"]
                    .as_str()
                    .is_some_and(|path| path.rsplit("::").next() == Some(expected_name))
            })
            .unwrap_or_else(|| {
                panic!("definition source facts omitted `{expected_name}`: {definitions:#?}")
            });
        assert!(
            definition["start-line"]
                .as_u64()
                .is_some_and(|line| line > 0)
        );
        assert!(definition["source-range"]["file"].is_string());
    }
    assert!(
        functions.iter().all(|function| {
            function["display-path"].as_str().is_none_or(|path| {
                !path.ends_with("::bodyless") && !path.ends_with("::foreign_declaration")
            })
        }),
        "bodyless declarations must not be synthesized into body facts"
    );
}

fn assert_policy_neutral_facts(facts: &serde_json::Value) {
    assert_json_keys_absent(
        facts,
        &[
            "compiler-fingerprint",
            "finding",
            "findings",
            "scope",
            "trace",
            "traces",
            "policy",
            "policies",
        ],
    );
}

#[test]
fn cargo_cache_persists_package_relative_definition_provenance() {
    let temp = tempfile::tempdir().expect("temp dir");
    fs::create_dir(temp.path().join("src")).expect("create source directory");
    fs::write(
        temp.path().join("Cargo.toml"),
        "[package]\nname = \"provenance-probe\"\nversion = \"1.2.3\"\nedition = \"2024\"\n\n[workspace]\n",
    )
    .expect("write Cargo manifest");
    fs::write(
        temp.path().join("src/lib.rs"),
        "pub trait Probe {\n    fn required(&self);\n}\n",
    )
    .expect("write package source");
    let cache_dir = temp.path().join("cache");
    let mut command = Command::new(env!("CARGO_BIN_EXE_cargo-sniff-test"));
    clean_cargo_package_env(&mut command);
    let _cargo_guard = lock_nested_cargo();
    let output = command
        .args(["--cache-dir"])
        .arg(&cache_dir)
        .args(["--message-format", "json", "--color", "never"])
        .current_dir(temp.path())
        .output()
        .expect("run Cargo frontend");
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let cache_path = artifact_cache_for_crate(&cache_dir, "provenance_probe");
    let cache: serde_json::Value = serde_json::from_slice(
        &fs::read(&cache_path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", cache_path.display())),
    )
    .expect("cache should contain JSON");
    assert_eq!(cache["artifact"]["package-name"], "provenance-probe");
    assert_eq!(cache["artifact"]["package-version"], "1.2.3");
    let source_files = cache["facts"]["source-files"]
        .as_array()
        .expect("source files");
    assert!(
        source_files
            .iter()
            .any(|source| source["logical-path"] == "src/lib.rs"),
        "source facts omitted the package-relative path: {source_files:#?}"
    );
    let required = cache["facts"]["definitions"]
        .as_array()
        .expect("definition sources")
        .iter()
        .find(|definition| {
            definition["display-path"]
                .as_str()
                .is_some_and(|path| path.ends_with("::Probe::required"))
        })
        .expect("required trait declaration definition source");
    assert_eq!(required["start-line"], 2);
}

fn assert_definition_backed_display_paths(value: &serde_json::Value, forbidden: &str) {
    match value {
        serde_json::Value::Object(fields) => {
            for (name, value) in fields {
                if name == "display-path" {
                    let path = value
                        .as_str()
                        .expect("display paths in artifact facts must be strings");
                    assert!(
                        !path.contains(forbidden),
                        "consumer-visible re-export leaked into display path `{path}`"
                    );
                }
                assert_definition_backed_display_paths(value, forbidden);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                assert_definition_backed_display_paths(value, forbidden);
            }
        }
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => {}
    }
}

fn assert_consumer_definition_paths(consumer_facts: &str, consumer_document: &serde_json::Value) {
    for expected in [
        r#""display-path":"core::slice::<impl [T]>::get_unchecked""#,
        r#""display-path":"core::ub_checks::assert_unsafe_precondition""#,
        r#""display-path":"core::panicking::panic_nounwind_fmt""#,
    ] {
        assert!(
            consumer_facts.contains(expected),
            "consumer facts omitted definition-backed path {expected}:\n{consumer_facts}"
        );
    }
    assert!(
        consumer_facts.contains(
            "core::definition_path_reexport::macros::internal::core::panicking::panic_nounwind_fmt"
        ),
        "the old session-visible path should remain available only as a policy alias"
    );
    assert_definition_backed_display_paths(
        consumer_document,
        "definition_path_reexport::macros::internal::core",
    );
}

#[test]
fn cached_definition_paths_ignore_dependency_reexports() {
    let temp = tempfile::tempdir().expect("temp dir");
    let source = temp.path().join("definition_path_reexport.rs");
    fs::write(
        &source,
        r"#![allow(dead_code)]

pub mod macros {
    pub mod internal {
        pub use core;
    }
}

pub fn exported(values: &[u8], index: usize) -> u8 {
    // SAFETY: this fixture intentionally models an audited caller.
    unsafe { *values.get_unchecked(index) }
}
",
    )
    .expect("write dependency source");
    let cache_dir = temp.path().join("cache");
    let dependency_rlib = temp.path().join("libdefinition_path_reexport.rlib");
    let output = run_dependency_unit(
        temp.path(),
        &cache_dir,
        "definition_path_reexport",
        &source,
        Some(&dependency_rlib),
        "json",
        &[],
    );
    assert_silent_success(&output, "dependency unit");

    let cache_path = artifact_cache_for_crate(&cache_dir, "definition_path_reexport");
    let serialized = fs::read_to_string(&cache_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", cache_path.display()));
    let defining_facts: serde_json::Value =
        serde_json::from_str(&serialized).expect("dependency cache should be JSON");
    assert_eq!(defining_facts["artifact"]["scope"], "dependency");

    assert!(
        serialized.contains("assert_unsafe_precondition"),
        "the fixture must exercise the core unsafe-precondition macro:\n{serialized}"
    );
    assert_definition_backed_display_paths(
        &defining_facts,
        "definition_path_reexport::macros::internal::core",
    );

    let workspace_source = temp.path().join("definition_path_consumer.rs");
    fs::write(
        &workspace_source,
        "pub fn exported(values: &[u8], index: usize) -> u8 {\n\
         definition_path_reexport::exported(values, index)\n\
         }\n",
    )
    .expect("write workspace source");
    let manifest = temp.path().join("sniff-test.toml");
    fs::write(
        &manifest,
        "[analysis]\n\
         report-roots = [\"definition_path_consumer::exported\"]\n\
         \n\
         [panics.lints]\n\
         compiler-assert = \"allow\"\n\
         panic-invocation = \"deny\"\n",
    )
    .expect("write manifest");
    let workspace = run_workspace_unit(
        temp.path(),
        &cache_dir,
        &manifest,
        "definition_path_consumer",
        &workspace_source,
        "json",
        |command| {
            command.arg("--extern").arg(format!(
                "definition_path_reexport={}",
                dependency_rlib.display()
            ));
        },
    );
    assert_success(&workspace, "workspace consumer");
    assert!(
        !String::from_utf8_lossy(&workspace.stdout).contains("panic-invocation"),
        "the default unsafe-precondition macro boundary must suppress its panic sink:\n{}",
        String::from_utf8_lossy(&workspace.stdout)
    );
    let consumer_cache = artifact_cache_for_crate(&cache_dir, "definition_path_consumer");
    let consumer_facts = fs::read_to_string(&consumer_cache).unwrap_or_else(|error| {
        panic!(
            "failed to read consumer cache {}: {error}",
            consumer_cache.display()
        )
    });
    let consumer_document: serde_json::Value =
        serde_json::from_str(&consumer_facts).expect("consumer cache should be JSON");
    assert_eq!(consumer_document["artifact"]["scope"], "workspace");

    assert!(
        consumer_facts.contains("assert_unsafe_precondition"),
        "the consumer fixture must extract the core unsafe-precondition macro:\n{consumer_facts}"
    );
    assert_consumer_definition_paths(&consumer_facts, &consumer_document);
}

#[test]
fn workspace_lint_policy_reinterprets_unchanged_dependency_facts() {
    let temp = tempfile::tempdir().expect("temp dir");
    let fixture = PolicyReinterpretationFixture::new(temp.path());
    let dependency_output = run_dependency_unit(
        temp.path(),
        &fixture.cache_dir,
        "policy_dependency",
        &fixture.dependency_source,
        Some(&fixture.dependency_rlib),
        "json",
        &["-Coverflow-checks=off"],
    );
    assert_silent_success(&dependency_output, "dependency unit");

    let dependency_cache = artifact_cache_for_crate(&fixture.cache_dir, "policy_dependency");
    let initial_bytes = fs::read(&dependency_cache)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", dependency_cache.display()));
    let initial_document: serde_json::Value =
        serde_json::from_slice(&initial_bytes).expect("dependency cache should contain JSON");
    assert_eq!(initial_document["format-version"], 29);
    assert_eq!(initial_document["artifact"]["scope"], "dependency");
    assert!(initial_document["facts"].get("tables").is_none());
    assert!(initial_document.get("analysis-id").is_none());
    let cache_modified_before = fs::metadata(&dependency_cache)
        .and_then(|metadata| metadata.modified())
        .expect("read dependency cache modification time");
    let rlib_modified_before = fs::metadata(&fixture.dependency_rlib)
        .and_then(|metadata| metadata.modified())
        .expect("read dependency artifact modification time");

    let run_workspace = |manifest: &Path| {
        run_workspace_unit(
            temp.path(),
            &fixture.cache_dir,
            manifest,
            "policy_workspace",
            &fixture.workspace_source,
            "json",
            |command| {
                command
                    .arg("--extern")
                    .arg(format!(
                        "policy_dependency={}",
                        fixture.dependency_rlib.display()
                    ))
                    // A workspace and dependency may legitimately use distinct Cargo
                    // package-profile compiler settings. Cache validity is bound to
                    // the dependency's loaded rustc identity, not this root's flags.
                    .arg("-Coverflow-checks=on");
            },
        )
    };

    let allowed = run_workspace(&fixture.allow_manifest);
    assert_success(&allowed, "allow-policy workspace unit");
    let allowed_report: serde_json::Value =
        serde_json::from_slice(&allowed.stdout).expect("parse allowed workspace report");
    assert_eq!(allowed_report["reason"], "sniff-test-artifact");
    assert_eq!(
        allowed_report["findings"],
        serde_json::json!([]),
        "allow policy should filter the dependency compiler assertion"
    );

    let denied = run_workspace(&fixture.deny_manifest);
    assert_success(&denied, "deny-policy workspace unit");
    let denied_report: serde_json::Value =
        serde_json::from_slice(&denied.stdout).expect("parse denied workspace report");
    assert_denied_dependency_bounds_check(&denied_report);

    let final_bytes = fs::read(&dependency_cache)
        .unwrap_or_else(|error| panic!("failed to reread {}: {error}", dependency_cache.display()));
    assert_eq!(
        final_bytes, initial_bytes,
        "lint-only workspace runs must not rewrite dependency facts"
    );
    assert_eq!(
        fs::metadata(&dependency_cache)
            .and_then(|metadata| metadata.modified())
            .expect("reread dependency cache modification time"),
        cache_modified_before,
        "lint-only workspace runs rewrote the dependency cache"
    );
    assert_eq!(
        fs::metadata(&fixture.dependency_rlib)
            .and_then(|metadata| metadata.modified())
            .expect("reread dependency artifact modification time"),
        rlib_modified_before,
        "workspace reinterpretation recompiled the dependency artifact"
    );
}

#[test]
fn dependency_compiler_settings_select_distinct_rustc_artifact_ids() {
    let temp = tempfile::tempdir().expect("temp dir");
    let source = temp.path().join("compiler_identity.rs");
    fs::write(
        &source,
        "pub fn indexed(values: &[u8], index: usize) -> u8 { values[index] }\n",
    )
    .expect("write dependency source");
    let cache_dir = temp.path().join("cache");

    for setting in ["off", "on"] {
        let artifact = temp
            .path()
            .join(format!("libcompiler_identity_{setting}.rlib"));
        let output = run_dependency_unit(
            temp.path(),
            &cache_dir,
            "compiler_identity",
            &source,
            Some(&artifact),
            "json",
            &[if setting == "on" {
                "-Coverflow-checks=on"
            } else {
                "-Coverflow-checks=off"
            }],
        );
        assert_silent_success(&output, "dependency compiler-setting variant");
    }

    let caches = artifact_caches_for_crate(&cache_dir, "compiler_identity");
    assert_eq!(
        caches.len(),
        2,
        "compiler settings that affect extracted MIR must select distinct rustc artifact IDs"
    );
    let identities = caches
        .iter()
        .map(|path| {
            let cache: serde_json::Value =
                serde_json::from_slice(&fs::read(path).expect("read artifact cache"))
                    .expect("artifact cache should contain JSON");
            cache["artifact"]["id"].clone()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        identities[0]["stable-crate-id"], identities[1]["stable-crate-id"],
        "the crate identity should remain stable"
    );
    assert_ne!(
        identities[0]["svh"], identities[1]["svh"],
        "rustc's SVH should distinguish compiler behavior"
    );
}

#[test]
fn cargo_output_suffix_does_not_change_rustc_artifact_identity() {
    let temp = tempfile::tempdir().expect("temp dir");
    let source = temp.path().join("output_shape_identity.rs");
    fs::write(&source, "pub fn dependency_body() {}\n").expect("write dependency source");
    let cache_dir = temp.path().join("cache");

    let rlib = run_dependency_unit(
        temp.path(),
        &cache_dir,
        "output_shape_identity",
        &source,
        None,
        "json",
        &["-Cextra-filename=-rlib"],
    );
    assert_silent_success(&rlib, "rlib dependency unit");
    let first_path = artifact_cache_for_crate(&cache_dir, "output_shape_identity");
    let first_cache: serde_json::Value =
        serde_json::from_slice(&fs::read(&first_path).expect("read rlib cache"))
            .expect("rlib cache should contain JSON");

    let renamed_rlib = run_dependency_unit(
        temp.path(),
        &cache_dir,
        "output_shape_identity",
        &source,
        None,
        "json",
        &["-Cextra-filename=-second"],
    );
    assert_silent_success(&renamed_rlib, "renamed rlib dependency unit");
    let caches = artifact_caches_for_crate(&cache_dir, "output_shape_identity");
    assert_eq!(
        caches,
        [first_path],
        "Cargo output suffixes must not create cache identities"
    );
    let second_cache: serde_json::Value =
        serde_json::from_slice(&fs::read(&caches[0]).expect("read renamed rlib cache"))
            .expect("renamed rlib cache should contain JSON");
    assert_eq!(
        first_cache["artifact"]["id"], second_cache["artifact"]["id"],
        "rustc should identify both output names as the same artifact"
    );
}

#[test]
fn ordinary_workspace_binary_is_interpreted_without_a_cache_identity() {
    let temp = tempfile::tempdir().expect("temp dir");
    let cache_dir = temp.path().join("cache");
    let dependency_source = temp.path().join("workspace_binary_dependency.rs");
    fs::write(&dependency_source, "pub fn touch() {}\n").expect("write dependency source");
    let dependency_rlib = temp.path().join("libworkspace_binary_dependency.rlib");
    let dependency = run_dependency_unit(
        temp.path(),
        &cache_dir,
        "workspace_binary_dependency",
        &dependency_source,
        Some(&dependency_rlib),
        "json",
        &[],
    );
    assert_silent_success(&dependency, "workspace binary dependency");

    let source = temp.path().join("workspace_binary.rs");
    fs::write(
        &source,
        "fn main() {\n    let unused = 1_u8;\n    workspace_binary_dependency::touch();\n}\n",
    )
    .expect("write workspace binary");
    let manifest = temp.path().join("sniff-test.toml");
    fs::write(
        &manifest,
        "[analysis]\nreport-roots = [\"workspace_binary::main\"]\n",
    )
    .expect("write manifest");
    let mut command = direct_driver_command();
    let output = command
        .args(["--manifest"])
        .arg(&manifest)
        .args(["--cache-dir"])
        .arg(&cache_dir)
        .args(["--message-format", "json", "--color", "never", "--"])
        .args([
            "--crate-name",
            "workspace_binary",
            "--crate-type",
            "bin",
            "--edition",
            "2024",
        ])
        .arg(&source)
        .arg("--extern")
        .arg(format!(
            "workspace_binary_dependency={}",
            dependency_rlib.display()
        ))
        .args([
            "--sysroot",
            rustc_sysroot().as_str(),
            "--emit=dep-info,metadata",
            "-C",
            "opt-level=3",
            "-C",
            "embed-bitcode=no",
            "-C",
            "metadata=1edabe6620e8238b",
            "-C",
            "extra-filename=-45e50dbbc42c973f",
            "-C",
            "strip=debuginfo",
            "-Z",
            "always-encode-mir",
            "-Z",
            "mir-opt-level=2",
            "-Z",
            "inline-mir=no",
            "-Z",
            "inline-mir-threshold=0",
            "-Z",
            "inline-mir-forwarder-threshold=0",
            "-Z",
            "inline-mir-hint-threshold=0",
            "-Z",
            "mir-enable-passes=-Inline,-ForceInline",
        ])
        .arg("-L")
        .arg(format!("dependency={}", temp.path().display()))
        .env("CARGO_PRIMARY_PACKAGE", "1")
        .current_dir(temp.path())
        .output()
        .expect("run workspace binary");

    assert_success(&output, "workspace binary");
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse workspace binary report");
    assert_eq!(report["artifact"]["crate-name"], "workspace_binary");
    assert!(
        artifact_caches_for_crate(&cache_dir, "workspace_binary").is_empty(),
        "ordinary binaries must not receive a synthetic persisted identity"
    );
    assert_eq!(
        artifact_caches_for_crate(&cache_dir, "workspace_binary_dependency").len(),
        1,
        "the dependency should retain its real rustc cache identity"
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the regression proves the cache identity, extracted marker delta, and workspace rejection together"
)]
fn stale_source_marker_facts_are_rejected_even_when_rustc_identity_is_unchanged() {
    let temp = tempfile::tempdir().expect("temp dir");
    let dependency_source = temp.path().join("stale_marker_dependency.rs");
    fs::write(
        &dependency_source,
        "pub fn read(pointer: *const u8) -> u8 {\n\
             // SAFETY: the caller guarantees that the byte is readable.\n\
             unsafe { *pointer }\n\
         }\n",
    )
    .expect("write marked dependency source");
    let dependency_rlib = temp.path().join("libstale_marker_dependency.rlib");
    let stale_cache_dir = temp.path().join("stale-cache");
    let marked = run_dependency_unit(
        temp.path(),
        &stale_cache_dir,
        "stale_marker_dependency",
        &dependency_source,
        Some(&dependency_rlib),
        "json",
        &[],
    );
    assert_silent_success(&marked, "marked dependency unit");
    let stale_cache = artifact_cache_for_crate(&stale_cache_dir, "stale_marker_dependency");
    let stale_document: serde_json::Value =
        serde_json::from_slice(&fs::read(&stale_cache).expect("read stale cache"))
            .expect("stale cache should contain JSON");
    assert!(
        artifact_marker_count(&stale_document) > 0,
        "the regression requires a cached source marker"
    );

    fs::write(
        &dependency_source,
        "pub fn read(pointer: *const u8) -> u8 {\n\
             // XAFETY: the caller guarantees that the byte is readable.\n\
             unsafe { *pointer }\n\
         }\n",
    )
    .expect("replace only the marker prefix with same-length text");
    let fresh_cache_dir = temp.path().join("fresh-cache");
    let unmarked = run_dependency_unit(
        temp.path(),
        &fresh_cache_dir,
        "stale_marker_dependency",
        &dependency_source,
        Some(&dependency_rlib),
        "json",
        &[],
    );
    assert_silent_success(&unmarked, "unmarked dependency unit");
    let fresh_cache = artifact_cache_for_crate(&fresh_cache_dir, "stale_marker_dependency");
    let fresh_document: serde_json::Value =
        serde_json::from_slice(&fs::read(&fresh_cache).expect("read fresh cache"))
            .expect("fresh cache should contain JSON");
    assert_eq!(
        artifact_marker_count(&fresh_document),
        0,
        "the replacement source must remove the cached marker semantics"
    );
    assert_eq!(
        stale_document["artifact"]["id"], fresh_document["artifact"]["id"],
        "ordinary marker comments are intentionally outside rustc's artifact identity"
    );

    let workspace_source = temp.path().join("stale_marker_workspace.rs");
    fs::write(
        &workspace_source,
        "pub fn workspace_root(pointer: *const u8) -> u8 {\n\
             stale_marker_dependency::read(pointer)\n\
         }\n",
    )
    .expect("write workspace source");
    let manifest = temp.path().join("sniff-test.toml");
    fs::write(
        &manifest,
        "[analysis]\n\
         report-roots = [\"stale_marker_workspace::workspace_root\"]\n\
         \n\
         [safety.lints]\n\
         unsafe-op-missing-justification = \"deny\"\n",
    )
    .expect("write manifest");
    let output = run_workspace_unit(
        temp.path(),
        &stale_cache_dir,
        &manifest,
        "stale_marker_workspace",
        &workspace_source,
        "human",
        |command| {
            command.arg("--extern").arg(format!(
                "stale_marker_dependency={}",
                dependency_rlib.display()
            ));
        },
    );

    assert!(!output.status.success(), "stale marker facts was accepted");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cached source marker facts"),
        "stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("content hash"),
        "source mismatch should explain the failed integrity check:\n{stderr}"
    );
}

#[test]
fn fixed_name_dependency_cache_must_match_the_crate_rustc_actually_loaded() {
    let temp = tempfile::tempdir().expect("temp dir");
    let dependency_source = temp.path().join("fixed_identity_dependency.rs");
    fs::write(
        &dependency_source,
        "pub fn dependency_value() -> u8 { 1 }\n",
    )
    .expect("write initial dependency source");
    // The output filename is intentionally unrelated to the crate metadata;
    // cache lookup must not infer artifact identity from this stem.
    let dependency_rlib = temp.path().join("libcustom-output-name.rlib");
    let cache_dir = temp.path().join("cache");
    let sysroot = rustc_sysroot();

    let analyzed_output = run_dependency_unit(
        temp.path(),
        &cache_dir,
        "fixed_identity_dependency",
        &dependency_source,
        Some(&dependency_rlib),
        "human",
        &[],
    );
    assert_success(&analyzed_output, "analyzed dependency");

    // Replace the exact same output filename without running sniff-test, so
    // the cache deliberately contains only the previous rustc identity.
    fs::write(
        &dependency_source,
        "pub fn dependency_value() -> u8 { 2 }\n",
    )
    .expect("replace dependency source");
    let rustc = std::env::var_os("RUSTC").map_or_else(|| PathBuf::from("rustc"), PathBuf::from);
    let replacement = Command::new(rustc)
        .args([
            "--crate-name",
            "fixed_identity_dependency",
            "--crate-type",
            "rlib",
            "--edition",
            "2024",
        ])
        .arg(&dependency_source)
        .arg("-o")
        .arg(&dependency_rlib)
        .args(["--sysroot", sysroot.as_str()])
        .current_dir(temp.path())
        .output()
        .expect("compile replacement dependency");
    assert!(
        replacement.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&replacement.stdout),
        String::from_utf8_lossy(&replacement.stderr)
    );

    let workspace_source = temp.path().join("fixed_identity_workspace.rs");
    fs::write(
        &workspace_source,
        "pub fn workspace_root() -> u8 { renamed_dependency::dependency_value() }\n",
    )
    .expect("write workspace source");
    let manifest = temp.path().join("sniff-test.toml");
    fs::write(
        &manifest,
        "[analysis]\nreport-roots = [\"fixed_identity_workspace::workspace_root\"]\n",
    )
    .expect("write manifest");
    let output = run_workspace_unit(
        temp.path(),
        &cache_dir,
        &manifest,
        "fixed_identity_workspace",
        &workspace_source,
        "human",
        |command| {
            command
                .arg("--extern")
                .arg(format!("renamed_dependency={}", dependency_rlib.display()));
        },
    );

    assert!(!output.status.success(), "stale cache was accepted");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("missing artifact facts for"),
        "stderr:\n{stderr}"
    );
    assert_eq!(
        stderr.matches("missing artifact facts for").count(),
        1,
        "the new rustc identity should be reported missing once\nstderr:\n{stderr}"
    );
}

#[test]
fn unused_dependency_facts_produce_no_workspace_findings() {
    let temp = tempfile::tempdir().expect("temp dir");
    let dependency_source = temp.path().join("unused_ir_dependency.rs");
    fs::write(
        &dependency_source,
        "pub fn unreachable_dependency_panic() { panic!(\"unused\") }\n",
    )
    .expect("write dependency source");
    let dependency_rlib = temp.path().join("libunused_ir_dependency.rlib");
    let cache_dir = temp.path().join("cache");
    let dependency_output = run_dependency_unit(
        temp.path(),
        &cache_dir,
        "unused_ir_dependency",
        &dependency_source,
        Some(&dependency_rlib),
        "json",
        &[],
    );
    assert_silent_success(&dependency_output, "unused dependency analysis");

    let workspace_source = temp.path().join("unused_ir_workspace.rs");
    fs::write(&workspace_source, "pub fn workspace_root() {}\n").expect("write workspace source");
    let manifest = temp.path().join("sniff-test.toml");
    fs::write(
        &manifest,
        "[analysis]\nreport-roots = [\"unused_ir_workspace::workspace_root\"]\n",
    )
    .expect("write manifest");
    let output = run_workspace_unit(
        temp.path(),
        &cache_dir,
        &manifest,
        "unused_ir_workspace",
        &workspace_source,
        "json",
        |command| {
            command
                .arg("-L")
                .arg(temp.path())
                .arg("--extern")
                .arg("unused_ir_dependency");
        },
    );
    assert_success(&output, "unused dependency workspace analysis");
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse workspace report");
    assert_eq!(report["findings"], serde_json::json!([]));
}

#[test]
fn cached_dependency_source_is_verified_before_rendering_a_snippet() {
    let temp = tempfile::tempdir().expect("temp dir");
    let dependency_source = temp.path().join("cached_source_dependency.rs");
    fs::write(
        &dependency_source,
        "pub fn indexed(values: &[u8], index: usize) -> u8 {\n    values[index]\n}\n",
    )
    .expect("write dependency source");
    let dependency_rlib = temp.path().join("libcached_source_dependency.rlib");
    let workspace_source = temp.path().join("cached_source_workspace.rs");
    fs::write(
        &workspace_source,
        "pub fn workspace_root(values: &[u8], index: usize) -> u8 {\n\
             cached_source_dependency::indexed(values, index)\n\
         }\n",
    )
    .expect("write workspace source");
    let manifest = temp.path().join("sniff-test.toml");
    fs::write(
        &manifest,
        "[analysis]\n\
         report-roots = [\"cached_source_workspace::workspace_root\"]\n\
         \n\
         [panics.lints]\n\
         compiler-assert = \"warn\"\n\
         panic-invocation = \"allow\"\n",
    )
    .expect("write manifest");

    let cache_dir = temp.path().join("cache");
    let dependency_output = run_dependency_unit(
        temp.path(),
        &cache_dir,
        "cached_source_dependency",
        &dependency_source,
        Some(&dependency_rlib),
        "human",
        &[],
    );
    assert_silent_success(&dependency_output, "dependency analysis");

    let run_workspace = |suffix: &str| {
        run_workspace_unit(
            temp.path(),
            &cache_dir,
            &manifest,
            "cached_source_workspace",
            &workspace_source,
            "human",
            |command| {
                command
                    .arg("--extern")
                    .arg(format!(
                        "cached_source_dependency={}",
                        dependency_rlib.display()
                    ))
                    .arg("-C")
                    .arg(format!("extra-filename={suffix}"));
            },
        )
    };

    let available = run_workspace("-source-available");
    assert_success(&available, "workspace unit with available source");
    let available_stderr = String::from_utf8_lossy(&available.stderr);
    assert!(
        available_stderr.contains("values[index]"),
        "verified dependency source should render its snippet:\n{available_stderr}"
    );
    assert!(
        available_stderr.contains(&dependency_source.display().to_string()),
        "verified dependency source should render its location:\n{available_stderr}"
    );

    fs::write(
        &dependency_source,
        "pub fn indexed(_values: &[u8], _index: usize) -> u8 {\n    7\n}\n",
    )
    .expect("replace dependency source without recompiling it");
    let unavailable = run_workspace("-source-unavailable");
    assert_success(&unavailable, "workspace unit with unavailable source");
    let unavailable_stderr = String::from_utf8_lossy(&unavailable.stderr);
    assert!(
        unavailable_stderr.contains("the recorded source location was unavailable"),
        "source verification failure should be explicit:\n{unavailable_stderr}"
    );
    assert!(
        !unavailable_stderr.contains("values[index]"),
        "stale source text must not be rendered:\n{unavailable_stderr}"
    );
    let span_locations = unavailable_stderr
        .lines()
        .filter(|line| line.trim_start().starts_with("-->"))
        .collect::<Vec<_>>();
    let workspace_source_path = workspace_source.display().to_string();
    assert!(
        !span_locations.is_empty()
            && span_locations
                .iter()
                .all(|location| location.contains(&workspace_source_path)),
        "only verified workspace locations may be spanned when the cached effect source is unavailable:\n{unavailable_stderr}"
    );
}

#[test]
fn workspace_unit_fails_when_required_extern_artifact_facts_are_missing() {
    let temp = tempfile::tempdir().expect("temp dir");
    let dependency_source = temp.path().join("required_ir_dep.rs");
    fs::write(&dependency_source, "pub fn dependency_body() {}\n")
        .expect("write dependency source");
    let dependency_rlib = temp.path().join("librequired_ir_dep.rlib");
    let cache_dir = temp.path().join("cache");
    let driver = PathBuf::from(env!("CARGO_BIN_EXE_sniff-test-driver"));

    let dependency_output = run_dependency_unit(
        temp.path(),
        &cache_dir,
        "required_ir_dep",
        &dependency_source,
        Some(&dependency_rlib),
        "json",
        &[],
    );
    assert_success(&dependency_output, "required dependency analysis");
    assert!(dependency_rlib.is_file(), "dependency rlib was not written");

    let dependency_cache = artifact_cache_for_crate(&cache_dir, "required_ir_dep");
    fs::remove_file(&dependency_cache)
        .unwrap_or_else(|error| panic!("failed to remove {}: {error}", dependency_cache.display()));

    let workspace_source = temp.path().join("workspace.rs");
    fs::write(
        &workspace_source,
        "pub fn workspace_root() { required_ir_dep::dependency_body(); }\n",
    )
    .expect("write workspace source");
    let mut workspace_command = Command::new(driver);
    clean_cargo_package_env(&mut workspace_command);
    let workspace_output = workspace_command
        .args(["--cache-dir"])
        .arg(&cache_dir)
        .args(["--message-format", "json", "--color", "never", "--"])
        .args([
            "--crate-name",
            "missing_ir_workspace",
            "--crate-type",
            "rlib",
            "--edition",
            "2024",
        ])
        .arg(&workspace_source)
        .arg("--extern")
        .arg(format!("required_ir_dep={}", dependency_rlib.display()))
        .args(["--sysroot", rustc_sysroot().as_str(), "-Zno-codegen"])
        .env("CARGO_PRIMARY_PACKAGE", "1")
        .current_dir(temp.path())
        .output()
        .expect("run workspace rustc unit");

    assert!(
        !workspace_output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&workspace_output.stdout),
        String::from_utf8_lossy(&workspace_output.stderr)
    );
    let stderr = String::from_utf8_lossy(&workspace_output.stderr);
    assert!(
        stderr.contains("error: failed to load required dependency artifact facts"),
        "stderr:\n{stderr}"
    );
    assert_eq!(
        stderr
            .matches("failed to load required dependency artifact facts")
            .count(),
        1,
        "missing required facts should emit exactly one tool error\nstderr:\n{stderr}"
    );
}

#[test]
fn cargo_frontend_ignores_compile_time_proc_macro_artifacts() {
    let temp = tempfile::tempdir().expect("temp dir");
    for package in ["app", "macros", "empty-macros", "seed"] {
        let source_dir = temp.path().join(package).join("src");
        fs::create_dir_all(&source_dir)
            .unwrap_or_else(|error| panic!("failed to create {}: {error}", source_dir.display()));
    }
    for (relative_path, contents) in [
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"app\", \"empty-macros\", \"macros\", \"seed\"]\nresolver = \"2\"\n",
        ),
        (
            "sniff-test.toml",
            "[panics]\npanic-sink-namespaces = [\"core::panicking::**\", \"std::panicking::**\"]\n",
        ),
        (
            "app/Cargo.toml",
            "[package]\nname = \"proc-macro-consumer\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[dependencies]\nempty-macros = { path = \"../empty-macros\" }\nworkspace-macros = { path = \"../macros\" }\n",
        ),
        (
            "app/src/lib.rs",
            "extern crate empty_macros;\nuse workspace_macros::passthrough;\n\n#[passthrough]\npub fn public_api() {}\n",
        ),
        (
            "macros/Cargo.toml",
            "[package]\nname = \"workspace-macros\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[lib]\nproc-macro = true\n",
        ),
        (
            "macros/src/lib.rs",
            "use proc_macro::TokenStream;\n\n#[proc_macro_attribute]\npub fn passthrough(_: TokenStream, item: TokenStream) -> TokenStream { item }\n",
        ),
        (
            "empty-macros/Cargo.toml",
            "[package]\nname = \"empty-macros\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[lib]\nproc-macro = true\n",
        ),
        ("empty-macros/src/lib.rs", ""),
        (
            "seed/Cargo.toml",
            "[package]\nname = \"old-diagnostic-seed\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        ),
        (
            "seed/src/lib.rs",
            "pub fn old_diagnostic() { panic!(\"old\"); }\n",
        ),
    ] {
        let path = temp.path().join(relative_path);
        fs::write(&path, contents)
            .unwrap_or_else(|error| panic!("failed to write {}: {error}", path.display()));
    }

    let binary = PathBuf::from(env!("CARGO_BIN_EXE_cargo-sniff-test"));
    let cache_dir = temp.path().join("cache");
    let _cargo_guard = lock_nested_cargo();
    let run_package = |package| {
        let mut command = Command::new(&binary);
        clean_cargo_package_env(&mut command);
        command
            .arg("--cache-dir")
            .arg(&cache_dir)
            .args(["--color", "never", "--", "-p", package])
            .current_dir(temp.path())
            .output()
            .unwrap_or_else(|error| panic!("failed to analyze {package}: {error}"))
    };
    let seed_output = run_package("old-diagnostic-seed");
    assert!(
        !seed_output.status.success(),
        "the seed panic should be denied:\n{}",
        String::from_utf8_lossy(&seed_output.stderr)
    );
    let seed_stderr = String::from_utf8_lossy(&seed_output.stderr);
    let old_handle = extract_group_handle(&seed_stderr);

    let output = run_package("workspace-macros");

    assert_success(&output, "proc-macro-only analysis");
    let mut explain = Command::new(&binary);
    clean_cargo_package_env(&mut explain);
    let explained = explain
        .args(["explain", &old_handle, "--cache-dir"])
        .arg(&cache_dir)
        .current_dir(temp.path())
        .output()
        .expect("query the report cleared by the successful proc-macro-only run");
    assert!(
        !explained.status.success(),
        "a successful run with no reporting units must replace the old explanation report:\n{}",
        String::from_utf8_lossy(&explained.stdout)
    );

    let consumer_output = run_package("proc-macro-consumer");
    assert_success(&consumer_output, "proc-macro consumer analysis");
    assert!(
        !String::from_utf8_lossy(&consumer_output.stderr)
            .contains("failed to load required dependency artifact facts"),
        "proc macros are compile-time tools, not runtime graph dependencies:\n{}",
        String::from_utf8_lossy(&consumer_output.stderr)
    );
}

#[test]
fn cargo_frontend_fails_when_dependency_analysis_cannot_be_cached() {
    let temp = tempfile::tempdir().expect("temp dir");
    let fixture = temp.path().join("dependency_identity");
    copy_fixture_dir(
        &repo_root().join("tests/fixtures/dependency_identity"),
        &fixture,
    )
    .expect("copy fixture");
    let cache_dir = temp.path().join("cache");
    fs::create_dir(&cache_dir).expect("create cache directory");
    fs::write(cache_dir.join("artifacts"), "occupied").expect("block artifact directory");

    let binary = PathBuf::from(env!("CARGO_BIN_EXE_cargo-sniff-test"));
    let mut command = Command::new(binary);
    clean_cargo_package_env(&mut command);
    let _cargo_guard = lock_nested_cargo();
    let output = command
        .args(["--cache-dir"])
        .arg(&cache_dir)
        .args(["--color", "never"])
        .current_dir(fixture.join("app"))
        .output()
        .expect("run cargo frontend");

    assert!(
        !output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("error: failed to write analysis cache"),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn direct_driver_fails_when_required_artifact_facts_cannot_be_cached() {
    let temp = tempfile::tempdir().expect("temp dir");
    let cache_file = temp.path().join("not-a-cache-directory");
    fs::write(&cache_file, "occupied").expect("write cache file");
    let fixture = repo_root().join("tests/fixtures/direct_panic");
    let source = fixture.join("src/lib.rs");
    let manifest = fixture.join("sniff-test.toml");
    let driver = PathBuf::from(env!("CARGO_BIN_EXE_sniff-test-driver"));
    let mut command = Command::new(driver);
    clean_cargo_package_env(&mut command);
    let output = command
        .args(["--manifest"])
        .arg(manifest)
        .args(["--cache-dir"])
        .arg(&cache_file)
        .args(["--message-format", "json", "--color", "never", "--"])
        .args([
            "--crate-name",
            "direct_cache_failure",
            "--crate-type",
            "lib",
            "--edition",
            "2024",
        ])
        .arg(source)
        .args(["--sysroot", rustc_sysroot().as_str(), "-Zno-codegen"])
        .current_dir(temp.path())
        .output()
        .expect("run driver");

    assert!(
        !output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("error: failed to write analysis cache"),
        "stderr:\n{stderr}"
    );
    assert_eq!(
        stderr.matches("failed to write analysis cache").count(),
        1,
        "cache persistence should emit exactly one tool error\nstderr:\n{stderr}"
    );
}

#[test]
fn invalid_config_is_rendered_once_by_cargo_frontend() {
    let temp = tempfile::tempdir().expect("temp dir");
    fs::create_dir(temp.path().join("src")).expect("create source directory");
    fs::write(
        temp.path().join("Cargo.toml"),
        "[package]\nname = \"invalid-config\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("write Cargo manifest");
    fs::write(temp.path().join("src/lib.rs"), "pub fn valid() {}\n").expect("write source");
    let manifest = temp.path().join("sniff-test.toml");
    fs::write(&manifest, "invalid = [").expect("write invalid sniff-test manifest");

    let binary = PathBuf::from(env!("CARGO_BIN_EXE_cargo-sniff-test"));
    let mut command = Command::new(binary);
    clean_cargo_package_env(&mut command);
    let _cargo_guard = lock_nested_cargo();
    let output = command
        .args(["--color", "never"])
        .current_dir(temp.path())
        .output()
        .expect("run cargo frontend");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    let load_context = stderr
        .find("error: failed to load configuration")
        .expect("outer load context should be rendered");
    let resolved_manifest = manifest.canonicalize().expect("canonicalize manifest");
    let path_context = stderr
        .find(&format!("failed to parse {}", resolved_manifest.display()))
        .expect("manifest path context should be rendered");
    let parser_source = stderr
        .find("TOML parse error")
        .expect("typed TOML parser source should be rendered");
    assert_eq!(
        load_context, 0,
        "outer load context should begin the error chain\nstderr: {stderr}"
    );
    assert!(
        load_context < path_context && path_context < parser_source,
        "error chain should render outer context before its sources\nstderr: {stderr}"
    );
    assert_eq!(
        stderr.matches("TOML parse error").count(),
        1,
        "the TOML diagnostic should appear once in the frontend error chain\nstderr: {stderr}"
    );
}

#[test]
fn invalid_config_is_rendered_by_driver_boundary() {
    let temp = tempfile::tempdir().expect("temp dir");
    let manifest = temp.path().join("sniff-test.toml");
    fs::write(&manifest, "invalid = [").expect("write invalid manifest");
    let source = repo_root().join("tests/fixtures/direct_panic/src/lib.rs");
    let driver = PathBuf::from(env!("CARGO_BIN_EXE_sniff-test-driver"));
    let mut command = Command::new(driver);
    clean_cargo_package_env(&mut command);
    let output = command
        .args(["--manifest"])
        .arg(&manifest)
        .args(["--message-format", "json", "--color", "never", "--"])
        .args([
            "--crate-name",
            "invalid_config",
            "--crate-type",
            "lib",
            "--edition",
            "2024",
        ])
        .arg(source)
        .args(["--sysroot", rustc_sysroot().as_str(), "-Zno-codegen"])
        .current_dir(temp.path())
        .output()
        .expect("run driver");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.starts_with("error: failed to load configuration\n\nCaused by:\n    "),
        "stderr: {stderr}"
    );
    assert!(stderr.contains(&manifest.display().to_string()));
    assert_eq!(
        stderr.matches("TOML parse error").count(),
        1,
        "the TOML diagnostic should appear once in the error chain\nstderr: {stderr}"
    );
}

#[test]
fn standalone_direct_driver_ignores_ambient_cargo_scope_environment() {
    let temp = tempfile::tempdir().expect("temp dir");
    let cargo_manifest = temp.path().join("missing/Cargo.toml");
    let source = repo_root().join("tests/fixtures/direct_panic/src/lib.rs");
    let driver = PathBuf::from(env!("CARGO_BIN_EXE_sniff-test-driver"));
    let mut command = Command::new(driver);
    clean_cargo_package_env(&mut command);
    let output = command
        .args(["--message-format", "json", "--color", "never", "--"])
        .args([
            "--crate-name",
            "invalid_cargo_manifest",
            "--crate-type",
            "lib",
            "--edition",
            "2024",
        ])
        .arg(source)
        .args(["--sysroot", rustc_sysroot().as_str(), "-Zno-codegen"])
        .env("CARGO_MANIFEST_PATH", &cargo_manifest)
        .env("CARGO_PRIMARY_PACKAGE", "1")
        .current_dir(temp.path())
        .output()
        .expect("run driver");

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("standalone workspace report");
    assert_eq!(report["artifact"]["crate-name"], "invalid_cargo_manifest");
}

#[test]
fn init_subcommand_writes_example_manifest() {
    let temp = tempfile::tempdir().expect("temp dir");
    let manifest = temp.path().join("custom-sniff-test.toml");
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_cargo-sniff-test"));
    let mut command = Command::new(binary);
    clean_cargo_package_env(&mut command);
    let output = command
        .args(["init", "--manifest"])
        .arg(&manifest)
        .current_dir(temp.path())
        .output()
        .expect("run init");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(manifest).expect("read generated manifest"),
        include_str!("../example-manifest.toml")
    );
}

#[test]
fn init_subcommand_reports_error_chain() {
    let temp = tempfile::tempdir().expect("temp dir");
    let manifest = temp.path().join("missing-parent/sniff-test.toml");
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_cargo-sniff-test"));
    let output = Command::new(binary)
        .args(["init", "--manifest"])
        .arg(&manifest)
        .output()
        .expect("run init");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.starts_with(&format!(
            "error: failed to write `{}`\n\nCaused by:\n    ",
            manifest.display()
        )),
        "stderr: {stderr}"
    );
}

#[test]
fn cargo_subcommand_token_is_accepted() {
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_cargo-sniff-test"));
    let output = Command::new(binary)
        .args(["sniff-test", "--help"])
        .output()
        .expect("run help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Usage: cargo sniff-test"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("--debug"), "stdout: {stdout}");
    assert!(!stdout.contains("--release"), "stdout: {stdout}");
}

#[test]
fn cargo_subcommand_uses_a_concise_explain_command_for_the_default_cache() {
    let fixture = repo_root().join("tests/fixtures/direct_panic");
    let temp = tempfile::Builder::new()
        .prefix("sniff-test-concise-explain-")
        .tempdir()
        .expect("temporary fixture directory");
    let root = temp.path().join("direct_panic");
    copy_fixture_dir(&fixture, &root).expect("copy direct panic fixture");
    let binary = fs::canonicalize(env!("CARGO_BIN_EXE_cargo-sniff-test"))
        .expect("canonical cargo-sniff-test binary");
    let mut search_path = vec![
        binary
            .parent()
            .expect("cargo-sniff-test binary directory")
            .to_owned(),
    ];
    search_path.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let search_path = std::env::join_paths(search_path).expect("frontend search path");

    let _cargo_guard = lock_nested_cargo();
    let mut analyze = Command::new("cargo");
    clean_cargo_package_env(&mut analyze);
    let analyzed = analyze
        .args(["sniff-test", "--color", "never"])
        .env("PATH", &search_path)
        .current_dir(&root)
        .output()
        .expect("run through Cargo's subcommand argument shape");
    let analyzed = CommandOutput::from_output(analyzed);
    assert_eq!(
        analyzed.status.code(),
        Some(101),
        "stderr:\n{}",
        analyzed.stderr
    );

    let handle = extract_group_handle(&analyzed.stderr);
    assert_eq!(
        extract_explain_command(&analyzed.stderr),
        format!("cargo sniff-test explain {handle}")
    );
    assert!(
        !analyzed.stderr.contains("--cache-dir"),
        "the default report should be rediscovered without exposing its cache path:\n{}",
        analyzed.stderr
    );

    let mut explain = Command::new("cargo");
    clean_cargo_package_env(&mut explain);
    let explained = explain
        .args(["sniff-test", "explain", &handle])
        .env("PATH", &search_path)
        .current_dir(&root)
        .output()
        .expect("execute the concise explanation command through Cargo's argument shape");
    assert!(
        explained.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&explained.stdout),
        String::from_utf8_lossy(&explained.stderr)
    );
}

#[test]
fn cargo_frontend_rejects_explicit_missing_manifest() {
    let temp = tempfile::tempdir().expect("temp dir");
    let manifest = temp.path().join("missing-sniff-test.toml");
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_cargo-sniff-test"));
    let mut command = Command::new(binary);
    clean_cargo_package_env(&mut command);
    let output = command
        .args(["--manifest"])
        .arg(&manifest)
        .current_dir(repo_root().join("tests/fixtures/direct_panic"))
        .output()
        .expect("run cargo frontend");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr,
        format!(
            "error: manifest path `{}` does not exist\n",
            manifest.display()
        )
    );
}

#[test]
fn direct_driver_rejects_explicit_missing_manifest() {
    let temp = tempfile::tempdir().expect("temp dir");
    let manifest = temp.path().join("missing-sniff-test.toml");
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_sniff-test-driver"));
    let output = Command::new(binary)
        .args(["--manifest"])
        .arg(&manifest)
        .args(["--", "--version"])
        .output()
        .expect("run direct driver");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr,
        format!(
            "error: manifest path `{}` does not exist\n",
            manifest.display()
        )
    );
}

#[test]
fn direct_driver_rejects_manifest_directory() {
    let temp = tempfile::tempdir().expect("temp dir");
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_sniff-test-driver"));
    let output = Command::new(binary)
        .args(["--manifest"])
        .arg(temp.path())
        .args(["--", "--version"])
        .output()
        .expect("run direct driver");

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        format!(
            "error: manifest path `{}` is a directory but expected a file\n",
            temp.path().display()
        )
    );
}

struct PolicyReinterpretationFixture {
    dependency_source: PathBuf,
    dependency_rlib: PathBuf,
    workspace_source: PathBuf,
    allow_manifest: PathBuf,
    deny_manifest: PathBuf,
    cache_dir: PathBuf,
}

impl PolicyReinterpretationFixture {
    fn new(root: &Path) -> Self {
        let dependency_source = root.join("policy_dependency.rs");
        fs::write(
            &dependency_source,
            "pub fn indexed(values: &[u8], index: usize) -> u8 { values[index] }\n",
        )
        .expect("write dependency source");
        let dependency_rlib = root.join("libpolicy_dependency.rlib");
        let workspace_source = root.join("policy_workspace.rs");
        fs::write(
            &workspace_source,
            "pub fn workspace_root(values: &[u8], index: usize) -> u8 {\n\
             policy_dependency::indexed(values, index)\n\
         }\n",
        )
        .expect("write workspace source");

        let allow_manifest = root.join("allow.toml");
        fs::write(
            &allow_manifest,
            "[analysis]\n\
             report-roots = [\"policy_workspace::workspace_root\"]\n\
             \n\
             [panics.lints]\n\
             compiler-assert = \"allow\"\n",
        )
        .expect("write allow manifest");
        let deny_manifest = root.join("deny.toml");
        fs::write(
            &deny_manifest,
            "[analysis]\n\
             report-roots = [\"policy_workspace::workspace_root\"]\n\
             \n\
             [panics.lints]\n\
             compiler-assert = \"deny\"\n",
        )
        .expect("write deny manifest");

        Self {
            dependency_source,
            dependency_rlib,
            workspace_source,
            allow_manifest,
            deny_manifest,
            cache_dir: root.join("cache"),
        }
    }
}

fn run_dependency_unit(
    current_dir: &Path,
    cache_dir: &Path,
    crate_name: &str,
    source: &Path,
    artifact: Option<&Path>,
    message_format: &str,
    rustc_args: &[&str],
) -> Output {
    let mut command = direct_driver_command();
    command
        .arg("--dependency")
        .args(["--cache-dir"])
        .arg(cache_dir)
        .args(["--message-format", message_format, "--color", "never", "--"])
        .args([
            "--crate-name",
            crate_name,
            "--crate-type",
            "rlib",
            "--edition",
            "2024",
        ])
        .arg(source);
    if let Some(artifact) = artifact {
        command.arg("-o").arg(artifact);
    }
    command
        .args(["--sysroot", rustc_sysroot().as_str()])
        .args(rustc_args)
        .current_dir(current_dir)
        .output()
        .expect("run dependency rustc unit")
}

fn run_workspace_unit(
    current_dir: &Path,
    cache_dir: &Path,
    manifest: &Path,
    crate_name: &str,
    source: &Path,
    message_format: &str,
    configure: impl FnOnce(&mut Command),
) -> Output {
    let mut command = direct_driver_command();
    command
        .args(["--manifest"])
        .arg(manifest)
        .args(["--cache-dir"])
        .arg(cache_dir)
        .args(["--message-format", message_format, "--color", "never", "--"])
        .args([
            "--crate-name",
            crate_name,
            "--crate-type",
            "lib",
            "--edition",
            "2024",
        ])
        .arg(source)
        .args(["--sysroot", rustc_sysroot().as_str(), "-Zno-codegen"])
        .env("CARGO_PRIMARY_PACKAGE", "1");
    configure(&mut command);
    command
        .current_dir(current_dir)
        .output()
        .expect("run workspace rustc unit")
}

fn direct_driver_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sniff-test-driver"));
    clean_cargo_package_env(&mut command);
    command
}

fn artifact_cache_for_crate(cache_dir: &Path, crate_name: &str) -> PathBuf {
    let matches = artifact_caches_for_crate(cache_dir, crate_name);
    match matches.as_slice() {
        [path] => path.clone(),
        [] => panic!("no artifact cache found for crate `{crate_name}`"),
        paths => panic!("multiple artifact caches found for crate `{crate_name}`: {paths:?}"),
    }
}

fn artifact_caches_for_crate(cache_dir: &Path, crate_name: &str) -> Vec<PathBuf> {
    let artifacts = cache_dir.join("artifacts");
    fs::read_dir(&artifacts)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", artifacts.display()))
        .filter_map(|entry| {
            let path = entry.expect("read artifact cache entry").path();
            let source = fs::read(&path).expect("read artifact cache");
            let cache: serde_json::Value =
                serde_json::from_slice(&source).expect("artifact cache should contain JSON");
            (cache["artifact"]["crate-name"] == crate_name).then_some(path)
        })
        .collect()
}

fn assert_success(output: &Output, context: &str) {
    assert!(
        output.status.success(),
        "{context}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_silent_success(output: &Output, context: &str) {
    assert_success(output, context);
    assert!(
        output.stdout.is_empty() && output.stderr.is_empty(),
        "{context} was not silent\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_denied_dependency_bounds_check(report: &serde_json::Value) {
    let findings = report["findings"]
        .as_array()
        .expect("workspace findings should be an array");
    assert!(
        findings.iter().any(|finding| {
            finding["level"] == "deny"
                && finding["kind"] == "compiler-assert"
                && finding["compiler-assert-kind"] == "bounds-check"
                && finding["trace"].as_array().is_some_and(|trace| {
                    trace.iter().any(|step| {
                        step.as_str()
                            .is_some_and(|step| step.contains("policy_dependency::indexed"))
                    })
                })
        }),
        "deny policy should reinterpret the cached dependency assertion:\n{report:#}"
    );
}

impl Case {
    fn new() -> Self {
        Self {
            denied: false,
            app_crate: false,
            color: "never",
            working_dir: None,
            config_append: "",
            args: &[],
            rustflags: None,
        }
    }

    fn denied(mut self) -> Self {
        self.denied = true;
        self
    }

    fn in_app(mut self) -> Self {
        self.app_crate = true;
        self
    }

    fn color(mut self, color: &'static str) -> Self {
        self.color = color;
        self
    }

    fn working_dir(mut self, working_dir: &'static str) -> Self {
        self.working_dir = Some(working_dir);
        self
    }

    fn config_append(mut self, config_append: &'static str) -> Self {
        self.config_append = config_append;
        self
    }

    fn args(mut self, args: &'static [&'static str]) -> Self {
        self.args = args;
        self
    }

    fn rustflags(mut self, rustflags: &'static str) -> Self {
        self.rustflags = Some(rustflags);
        self
    }
}

fn run_named_case(name: &'static str, fixture_name: &'static str, case: &Case) {
    let repo = repo_root();
    let sysroot = rustc_sysroot();
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_cargo-sniff-test"));
    let (output, fixture_root, _temp) = run_case(&repo, &binary, name, fixture_name, case);

    let expected_exit = if case.denied { 101 } else { 0 };
    assert_eq!(
        output.status.code(),
        Some(expected_exit),
        "{name} ({fixture_name}): command exited {:?}, expected {}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        expected_exit,
        output.stdout,
        output.stderr
    );

    let snapshot = render_snapshot(
        output.status,
        &output.stdout,
        &output.stderr,
        &fixture_root,
        sysroot.as_str(),
    );
    assert_public_output_uses_human_words(name, &snapshot);
    insta::assert_snapshot!(name, snapshot);
}

fn assert_panic_axiom_lint_codes(stderr: &str) {
    const EXPECTED: [&str; 3] = [
        "[sniff-test::panics::compiler-assert-division-by-zero]",
        "[sniff-test::panics::compiler-assert-bounds-check]",
        "[sniff-test::panics::compiler-assert-remainder-by-zero]",
    ];

    for lint_code in EXPECTED {
        assert_eq!(
            stderr.matches(lint_code).count(),
            1,
            "expected exactly one `{lint_code}` diagnostic:\n{stderr}"
        );
    }
    assert_eq!(
        stderr
            .matches("[sniff-test::panics::compiler-assert-")
            .count(),
        EXPECTED.len(),
        "unexpected compiler-assert lint code:\n{stderr}"
    );
}

fn run_case(
    repo: &Path,
    binary: &Path,
    name: &str,
    fixture_name: &str,
    case: &Case,
) -> (CommandOutput, PathBuf, tempfile::TempDir) {
    let fixture = repo.join("tests/fixtures").join(fixture_name);
    assert!(
        fixture.exists(),
        "{name} ({fixture_name}): missing fixture {}",
        fixture.display()
    );

    let temp = tempfile::Builder::new()
        .prefix(&format!("sniff-test-cli-{name}-"))
        .tempdir()
        .unwrap_or_else(|error| panic!("{name}: failed to create temp dir: {error}"));
    let root = temp.path().join(fixture_name);
    copy_fixture_dir(&fixture, &root)
        .unwrap_or_else(|error| panic!("{name}: failed to copy fixture: {error}"));

    let crate_dir = if case.app_crate { "app" } else { "" };
    if !case.config_append.is_empty() {
        let config = root.join(crate_dir).join("sniff-test.toml");
        let existing = fs::read_to_string(&config)
            .unwrap_or_else(|error| panic!("{name}: failed to read config: {error}"));
        fs::write(config, existing + case.config_append)
            .unwrap_or_else(|error| panic!("{name}: failed to update config: {error}"));
    }

    let working_dir = root.join(case.working_dir.unwrap_or(crate_dir));
    let _cargo_guard = lock_nested_cargo();
    let output = run_cargo_sniff_test(binary, &working_dir, name, case);
    (output, root, temp)
}

fn run_cargo_sniff_test(
    binary: &Path,
    working_dir: &Path,
    name: &str,
    case: &Case,
) -> CommandOutput {
    let mut command = Command::new(binary);
    clean_cargo_package_env(&mut command);
    if let Some(rustflags) = case.rustflags {
        command.env("RUSTFLAGS", rustflags);
    }
    let output = command
        .args(["--color", case.color])
        .args(case.args)
        .current_dir(working_dir)
        .output()
        .unwrap_or_else(|error| panic!("{name}: failed to run {}: {error}", binary.display()));
    CommandOutput::from_output(output)
}

#[test]
fn snapshot_normalization_hides_the_internal_cache_format_version() {
    let normalized = normalize_line(
        "/workspace/target/sniff-test/sniff-test-cache/v25/explain.json",
        Path::new("/fixtures/demo"),
        "/unrelated-sysroot",
    );

    assert_eq!(
        normalized,
        "/workspace/target/sniff-test/sniff-test-cache/v[FORMAT]/explain.json"
    );
}

fn assert_json_keys_absent(value: &serde_json::Value, forbidden: &[&str]) {
    match value {
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                assert!(
                    !forbidden.contains(&key.as_str()),
                    "serialized artifact facts contains forbidden `{key}` field"
                );
                assert_json_keys_absent(value, forbidden);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                assert_json_keys_absent(value, forbidden);
            }
        }
        _ => {}
    }
}

fn artifact_marker_count(cache: &serde_json::Value) -> usize {
    cache["facts"]["functions"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|function| function["markers"].as_array())
        .map(Vec::len)
        .sum()
}
