mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

use common::{
    COMPILER_DEBUG_FRAGMENTS, CommandOutput, assert_public_output_uses_human_words,
    clean_cargo_package_env, copy_fixture_dir, extract_group_handle, lock_nested_cargo,
    normalize_path, render_snapshot, repo_root, rustc_sysroot,
};

struct Case {
    app_crate: bool,
    args: &'static [&'static str],
    denied: bool,
    full_report: bool,
    human_snapshot: Option<&'static str>,
}

impl Case {
    fn new() -> Self {
        Self {
            app_crate: false,
            args: &[],
            denied: false,
            full_report: false,
            human_snapshot: None,
        }
    }

    fn in_app(mut self) -> Self {
        self.app_crate = true;
        self
    }

    fn args(mut self, args: &'static [&'static str]) -> Self {
        self.args = args;
        self
    }

    fn denied(mut self) -> Self {
        self.denied = true;
        self
    }

    fn human_snapshot(mut self, name: &'static str) -> Self {
        self.human_snapshot = Some(name);
        self
    }

    fn full_report(mut self) -> Self {
        self.full_report = true;
        self
    }
}

macro_rules! fixture_cases {
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

fixture_cases! {
    "dependency_closure_bodies" => {
        dependency_closure_bodies => Case::new().in_app().denied();
        dependency_nested_closure_bodies => Case::new().in_app()
            .args(&["--manifest", "nested.toml"]).denied();
        dependency_returned_closure_bodies => Case::new().in_app()
            .args(&["--manifest", "returned.toml"]).denied();
        dependency_closure_concrete_dispatch => Case::new().in_app()
            .args(&["--manifest", "dispatch.toml"]).denied();
        dependency_closure_justifications => Case::new().in_app()
            .args(&["--manifest", "justified.toml"]);
    }
    "executable_artifact" => {
        executable_artifact =>
            Case::new().full_report();
    }
    "panic_axioms" => {
        panic_axioms => Case::new().denied()
            .human_snapshot("compiler_assert_diagnostics");
    }
    "generic_roots" => {
        generic_roots => Case::new().denied();
    }
    "direct_panic" => {
        direct_panic => Case::new().denied();
    }
    "async_runtime_bodies" => {
        async_runtime_bodies => Case::new().denied();
    }
    "target_feature_call_safety" => {
        target_feature_call_safety =>
            Case::new()
                .denied();
    }
    "closure_call_graph" => {
        closure_call_graph => Case::new().denied();
    }
    "custom_index_impl" => {
        custom_index_impl => Case::new();
    }
    "trait_default_method" => {
        trait_default_method => Case::new().denied();
    }
    "dyn_dispatch_call_site" => {
        dyn_dispatch_uses_trait_declaration_contract => Case::new().denied();
    }
    "supertrait_dyn_dispatch" => {
        supertrait_dyn_dispatch => Case::new()
            .denied();
    }
    "contract_overrides" => {
        contract_overrides => Case::new();
    }
    "source_contract_overrides" => {
        source_contract_overrides_match_only_the_selected_definition => Case::new();
    }
    "effect_marker_paths" => {
        effect_markers_preserve_path_specific_coverage =>
            Case::new().denied();
    }
    "release_pruning" => {
        release_pruning => Case::new().denied();
    }
    "optimizer_pruning" => {
        optimizer_pruning => Case::new();
    }
    "feature_gated" => {
        feature_gated => Case::new()
            .args(&["--", "--features", "dangerous"])
            .denied();
    }
    "suppression" => {
        suppression => Case::new().denied();
    }
    "dependency_obligation" => {
        dependency_obligation => Case::new().in_app()
            .human_snapshot("dependency_warning_footer");
    }
    "dependency_safety" => {
        dependency_safety => Case::new()
            .in_app()
            .denied()
            .human_snapshot("dependency_safety_diagnostics");
    }
    "dependency_unsafe_trait_call" => {
        dependency_unsafe_trait_call =>
            Case::new()
                .in_app()
                .denied();
    }
    "partial_effect_requirements" => {
        partial_effect_requirements => Case::new()
            .in_app()
            .denied();
    }
    "dependency_generic_private_panic" => {
        dependency_private_helper_trace =>
            Case::new()
                .in_app()
                .denied();
    }
    "dependency_identity" => {
        dependency_foreign_impl_identity =>
            Case::new()
                .in_app()
                .denied();
    }
    "dependency_generic_local_impl" => {
        dependency_generic_dispatch =>
            Case::new()
                .in_app()
                .denied();
    }
    "dependency_transitive_panic" => {
        dependency_transitive_panic => Case::new()
            .in_app()
            .denied()
            .human_snapshot("dependency_panic_diagnostics");
    }
    "std_trait_impl_glob" => {
        std_trait_impl_glob => Case::new();
    }
    "std_collection_init" => {
        std_collection_init => Case::new();
    }
    "unsafe_ops" => {
        unsafe_ops => Case::new();
    }
    "unsafe_closure_inherit" => {
        unsafe_closure_inherit => Case::new();
    }
    "trace_depth_limit" => {
        trace_depth_limit => Case::new()
            .denied();
    }
    "state_budget" => {
        state_budget => Case::new()
            .denied();
    }
    "indirect_calls" => {
        indirect_calls => Case::new()
            .human_snapshot("unresolved_call_target_diagnostics");
    }
    "chain_markers" => {
        chain_markers => Case::new();
    }
    "visibility_roots" => {
        visibility_roots => Case::new().denied();
    }
    "vendored_dep" => {
        vendored_dep => Case::new();
    }
    "safe_markers" => {
        safe_markers => Case::new().denied()
            .human_snapshot("compact_stack_hint");
    }
    "justification_above_attr" => {
        justification_above_attr => Case::new();
    }
    "panic_requirements" => {
        panic_requirements => Case::new();
    }
    "ambiguous_markers" => {
        ambiguous_markers => Case::new()
            .denied()
            .human_snapshot("ambiguous_marker_diagnostics");
    }
    "ambiguous_safety" => {
        ambiguous_safety => Case::new()
            .denied()
            .human_snapshot("ambiguous_safety_diagnostics");
        ambiguous_safety_macro_shared =>
            Case::new()
                .args(&["--manifest", "macro-shared.toml"])
                .denied()
                .human_snapshot("ambiguous_safety_macro_shared_diagnostics");
        ambiguous_safety_generic_instances =>
            Case::new()
                .args(&["--manifest", "generic-instances.toml"])
                .denied();
    }
    "safety_contract_requirements" => {
        safety_contracts_preserve_call_and_obligation_requirements => Case::new()
            .human_snapshot("safety_contract_requirement_diagnostics");
    }
    "structured_safety_doc" => {
        structured_safety_docs_require_each_named_justification => Case::new();
    }
    "structured_effect_doc_default" => {
        structured_effect_docs_allow_any_justification_by_default => Case::new();
    }
    "safety_callable_sites" => {
        safety_callable_sites => Case::new();
    }
    "macro_expansion" => {
        macro_expansion => Case::new().denied();
        macro_expansion_source_callsite => Case::new()
            .args(&["--manifest", "source-callsite.toml"])
            .denied();
    }
    "macro_marker_instances" => {
        macro_marker_instances =>
            Case::new()
                .denied();
    }
    "trusted_boundaries" => {
        trusted_boundaries => Case::new()
            .human_snapshot("trusted_boundary_diagnostics");
        trusted_unresolved_boundaries => Case::new()
            .args(&["--manifest", "trusted-unresolved.toml"]);
    }
    "report_roots" => {
        report_roots_public => Case::new().denied();
        report_roots_all => Case::new()
            .args(&["--manifest", "all.toml"])
            .denied();
        report_roots_explicit => Case::new()
            .args(&["--manifest", "explicit.toml"])
            .denied();
    }
}

#[test]
fn source_aggregation_json_retains_each_report_root() {
    let (analyzed, temp) = run_named_case(
        "source_aggregation_json_retains_each_report_root",
        "source_aggregation",
        &Case::new()
            .denied()
            .human_snapshot("source_aggregation_collapses_only_human_diagnostics"),
    );
    if !cfg!(unix) {
        return;
    }
    let root = temp.path().join("source_aggregation");
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_cargo-sniff-test"));
    let handle = extract_group_handle(&analyzed.stderr);
    let explained = Command::new(&binary)
        .args(["explain", &handle, "--color", "never"])
        .current_dir(&root)
        .output()
        .expect("explain shared source paths");
    assert!(explained.status.success(), "{explained:?}");
    let explanation = String::from_utf8(explained.stdout).expect("explanation should be utf-8");
    let help = explanation.find("= help").expect("remediation help");
    for root in ["first_api", "second_api"] {
        let edge = format!("source_aggregation::{root} --direct-call->");
        let path = explanation.find(&edge).expect("retain every root's path");
        assert!(path < help, "all paths must precede help:\n{explanation}");
    }
    let trace_steps = explanation.matches("effect trace step ").count();
    assert!(
        trace_steps >= 2,
        "explain should retain native trace notes for both roots:\n{explanation}"
    );
    assert_eq!(
        explanation.matches("report root -> effect source").count(),
        trace_steps,
        "each native trace note should retain its direction:\n{explanation}"
    );
}

fn run_named_case(
    name: &'static str,
    fixture_name: &'static str,
    case: &Case,
) -> (CommandOutput, tempfile::TempDir) {
    let repo = repo_root();
    let cargo = PathBuf::from(env!("CARGO_BIN_EXE_cargo-sniff-test"));
    let sysroot = rustc_sysroot();
    let (output, temp) = run_case(&repo, &cargo, name, fixture_name, case);
    let root = temp.path().join(fixture_name);
    let messages = parse_messages(&output, &root, &sysroot, name, fixture_name);
    if let Some(name) = case.human_snapshot {
        let snapshot = render_snapshot(output.status, "", &output.stderr, &root, &sysroot);
        assert_public_output_uses_human_words(name, &snapshot);
        // Keep the existing CLI snapshots while checking both streams in one run.
        let mut settings = insta::Settings::clone_current();
        settings.set_prepend_module_to_snapshot(false);
        settings.bind(|| insta::assert_snapshot!(format!("cli__{name}"), snapshot));
    }
    if case.full_report {
        insta::assert_json_snapshot!(name, messages);
    } else {
        let [report] = messages.as_slice() else {
            panic!("{name}: expected one workspace report, got {messages:?}");
        };
        insta::assert_json_snapshot!(name, report["findings"]);
    }
    (output, temp)
}

fn run_case(
    repo: &Path,
    cargo: &Path,
    name: &str,
    fixture_name: &str,
    case: &Case,
) -> (CommandOutput, tempfile::TempDir) {
    let fixture = repo.join("tests/fixtures").join(fixture_name);
    assert!(
        fixture.exists(),
        "{name} ({fixture_name}): missing fixture {}",
        fixture.display()
    );

    let temp = tempfile::Builder::new()
        .prefix(&format!("sniff-test-{name}-"))
        .tempdir()
        .unwrap_or_else(|error| panic!("{name}: failed to create temp dir: {error}"));
    let root = temp.path().join(fixture_name);
    copy_fixture_dir(&fixture, &root)
        .unwrap_or_else(|error| panic!("{name}: failed to copy fixture: {error}"));

    let output = {
        let _cargo_guard = lock_nested_cargo();
        let crate_dir = if case.app_crate {
            root.join("app")
        } else {
            root.clone()
        };
        let mut command = Command::new(cargo);
        clean_cargo_package_env(&mut command);
        let output = command
            .args(["--message-format", "json", "--color", "never"])
            .args(case.args)
            .current_dir(crate_dir)
            .output()
            .unwrap_or_else(|error| panic!("{name}: failed to run {}: {error}", cargo.display()));
        CommandOutput::from_output(output)
    };
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
    if case.denied {
        assert!(
            output.stderr.contains("error:"),
            "{name} ({fixture_name}): denied findings must fail through rustc/Cargo\nstderr:\n{}",
            output.stderr
        );
    }

    (output, temp)
}

fn parse_messages(
    output: &CommandOutput,
    root: &Path,
    sysroot: &str,
    name: &str,
    fixture_name: &str,
) -> Vec<Value> {
    let mut messages = output
        .stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let mut value = serde_json::from_str::<Value>(line).unwrap_or_else(|error| {
                panic!("{name} ({fixture_name}): invalid JSON line: {error}\n{line}")
            });
            normalize_json(&mut value, root, sysroot);
            assert_finding_discriminators(&value);
            value
        })
        .collect::<Vec<_>>();
    assert!(
        !messages.is_empty(),
        "{name} ({fixture_name}): no JSON messages emitted"
    );

    // Ordering is not the contract here; Cargo/rustc can interleave reports.
    messages.sort_by_key(message_sort_key);
    messages
}

fn assert_finding_discriminators(report: &Value) {
    let Some(findings) = report.get("findings").and_then(Value::as_array) else {
        return;
    };
    for finding in findings {
        let kind = finding["kind"]
            .as_str()
            .expect("finding kind should be a string");
        assert!(
            finding.get("effect").is_none(),
            "finding `{kind}` should be discriminated by kind, not a redundant effect field: \
             {finding}"
        );
        assert!(
            !matches!(
                kind,
                "cached-dependency-panic"
                    | "ambiguous-effect-marker"
                    | "ambiguous-effect-requirement"
                    | "analysis-incomplete"
            ),
            "finding `{kind}` must use the workspace interpreter's policy-domain discriminator: \
             {finding}"
        );
        let rendered = finding.to_string();
        for fragment in COMPILER_DEBUG_FRAGMENTS {
            assert!(
                !rendered.contains(fragment),
                "finding `{kind}` contains compiler debug output `{fragment}`: {finding}"
            );
        }
    }
}

fn normalize_json(value: &mut Value, fixture_root: &Path, sysroot: &str) {
    // Keep snapshots about report content, not run-local paths or fingerprints.
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if key == "rustc-version" {
                    *value = Value::String(String::from("[RUSTC_VERSION]"));
                } else {
                    normalize_json(value, fixture_root, sysroot);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                normalize_json(value, fixture_root, sysroot);
            }
        }
        Value::String(text) => {
            *text = normalize_path(text, fixture_root, "[FIXTURE]");
            *text = normalize_path(text, Path::new(sysroot), "[SYSROOT]");
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn message_sort_key(message: &Value) -> (String, String) {
    let artifact = message.get("artifact").unwrap_or(&Value::Null);
    (
        json_string(message, "reason"),
        json_string(artifact, "crate-name"),
    )
}

fn json_string(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

#[test]
fn fixture_copy_excludes_cargo_target_directories() {
    let temp = tempfile::tempdir().expect("temporary directory should be created");
    let source = temp.path().join("source");
    let destination = temp.path().join("destination");
    let nested = source.join("nested");
    let source_module = source.join("src/target");

    fs::create_dir_all(source.join("target")).expect("root target directory should be created");
    fs::create_dir_all(nested.join("target")).expect("nested target directory should be created");
    fs::create_dir_all(&source_module).expect("source module directory should be created");
    fs::write(source.join("Cargo.toml"), "[workspace]").expect("root manifest should be written");
    fs::write(nested.join("Cargo.toml"), "[workspace]").expect("nested manifest should be written");
    fs::write(source.join("Cargo.lock"), "lockfile").expect("fixture lockfile should be written");
    fs::write(source.join("target/root-cache"), "cache")
        .expect("root target cache should be written");
    fs::write(nested.join("source.rs"), "fn fixture() {}")
        .expect("nested fixture source should be written");
    fs::write(nested.join("target/nested-cache"), "cache")
        .expect("nested target cache should be written");
    fs::write(source_module.join("module.rs"), "pub struct Target;")
        .expect("legitimate target module should be written");

    copy_fixture_dir(&source, &destination).expect("fixture should be copied");

    assert_eq!(
        fs::read_to_string(destination.join("Cargo.lock"))
            .expect("Cargo.lock should remain part of the fixture"),
        "lockfile"
    );
    assert!(destination.join("nested/source.rs").is_file());
    assert!(destination.join("src/target/module.rs").is_file());
    assert!(!destination.join("target").exists());
    assert!(!destination.join("nested/target").exists());
}
