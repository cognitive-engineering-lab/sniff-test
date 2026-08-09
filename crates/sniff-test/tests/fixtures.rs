mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

use common::{
    COMPILER_DEBUG_FRAGMENTS, CommandOutput, clean_cargo_package_env, copy_dir_all,
    lock_nested_cargo, repo_root, rustc_sysroot,
};

struct Case {
    app_crate: bool,
    args: &'static [&'static str],
    denied: bool,
    full_report: bool,
}

impl Case {
    fn new() -> Self {
        Self {
            app_crate: false,
            args: &[],
            denied: false,
            full_report: false,
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
    "executable_artifact" => {
        executable_artifact =>
            Case::new().full_report();
    }
    "panic_axioms" => {
        panic_axioms => Case::new().denied();
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
        custom_index_impl => Case::new().denied();
    }
    "trait_default_method" => {
        trait_default_method => Case::new().denied();
    }
    "dyn_dispatch_call_site" => {
        dyn_dispatch_call_site => Case::new().denied();
    }
    "dyn_dispatch_same_trait" => {
        dyn_dispatch_same_trait => Case::new().denied();
    }
    "supertrait_dyn_dispatch" => {
        supertrait_dyn_dispatch => Case::new()
            .denied();
    }
    "documented_obligation" => {
        documented_obligation => Case::new();
    }
    "contract_overrides" => {
        contract_overrides => Case::new();
    }
    "converging_effect_paths" => {
        converging_effect_paths =>
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
        dependency_obligation => Case::new().in_app();
    }
    "dependency_safety" => {
        dependency_safety => Case::new()
            .in_app()
            .denied();
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
            .denied();
    }
    "std_trait_impl_glob" => {
        std_trait_impl_glob => Case::new();
    }
    "unsafe_ops" => {
        unsafe_ops => Case::new();
    }
    "unsafe_closure_inherit" => {
        unsafe_closure_inherit => Case::new();
    }
    "node_limit" => {
        node_limit => Case::new()
            .denied();
    }
    "indirect_calls" => {
        indirect_calls => Case::new();
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
        safe_markers => Case::new().denied();
    }
    "transitive_effect_markers" => {
        transitive_effect_markers => Case::new()
            .denied();
    }
    "panic_requirements" => {
        panic_requirements => Case::new();
    }
    "ambiguous_markers" => {
        ambiguous_markers => Case::new()
            .denied();
    }
    "ambiguous_safety" => {
        ambiguous_safety => Case::new()
            .denied();
        ambiguous_safety_macro_shared =>
            Case::new()
                .args(&["--manifest", "macro-shared.toml"])
                .denied();
    }
    "safety_requirements" => {
        safety_requirements => Case::new();
    }
    "safety_obligations" => {
        safety_obligations => Case::new();
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
        trusted_boundaries => Case::new();
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

fn run_named_case(name: &'static str, fixture_name: &'static str, case: &Case) {
    let repo = repo_root();
    let cargo = PathBuf::from(env!("CARGO_BIN_EXE_cargo-sniff-test"));
    let sysroot = rustc_sysroot();
    let messages = run_case(&repo, &cargo, &sysroot, name, fixture_name, case);
    if case.full_report {
        insta::assert_json_snapshot!(name, messages);
    } else {
        let [report] = messages.as_slice() else {
            panic!("{name}: expected one workspace report, got {messages:?}");
        };
        insta::assert_json_snapshot!(name, report["findings"]);
    }
}

fn run_case(
    repo: &Path,
    cargo: &Path,
    sysroot: &str,
    name: &str,
    fixture_name: &str,
    case: &Case,
) -> Vec<Value> {
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
    copy_dir_all(&fixture, &root)
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

    parse_messages(&output, &root, sysroot, name, fixture_name)
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
            *text = text
                .replace(&fixture_root.display().to_string(), "[FIXTURE]")
                .replace(sysroot, "[SYSROOT]");
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
