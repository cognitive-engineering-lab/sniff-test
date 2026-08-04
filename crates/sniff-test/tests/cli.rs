mod common;

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::{
    CommandOutput, clean_cargo_package_env, copy_dir_all, lock_nested_cargo, repo_root,
    rustc_sysroot,
};

#[derive(Clone, Copy, Debug)]
struct Case {
    behavior: &'static str,
    expected_exit: i32,
    crate_dir: &'static str,
    working_dir: Option<&'static str>,
    config_append: &'static str,
    args: &'static [&'static str],
    envs: &'static [(&'static str, &'static str)],
}

macro_rules! cli_cases {
    ($($fixture:literal => { $($case:ident => $spec:expr;)+ })+) => {
        $(
            $(
                #[test]
                fn $case() {
                    run_named_case(stringify!($case), $fixture, $spec);
                }
            )+
        )+
    };
}

cli_cases! {
    "direct_panic" => {
        panic_invocation_can_be_allowed => Case::new("panic invocation allow policy")
            .config_append("\n[panics.lints]\npanic-invocation = \"allow\"\n");
    }
    "safe_markers" => {
        compact_stack_hint => Case::new("compact stack hint").exit_code(101);
        full_stack_trace => Case::new("full stack trace")
            .exit_code(101)
            .config_append("\n[analysis]\nshow-full-stack-trace = true\n");
    }
    "dependency_obligation" => {
        dependency_warning_footer => Case::new("dependency warning footer").crate_dir("app");
    }
    "dependency_identity" => {
        cached_dependency_raw_panic_diagnostics => Case::new("cached dependency raw panic diagnostics")
            .crate_dir("app")
            .exit_code(101);
    }
    "dependency_safety" => {
        cached_raw_pointer_override_applies =>
            Case::new("cached raw pointer override")
                .crate_dir("app")
                .config_append(
                    "\nraw-pointer-dereference-missing-justification = \"allow\"\n",
                );
    }
    "dependency_assert_kinds" => {
        cached_compiler_assert_override_applies =>
            Case::new("cached compiler assert override")
                .crate_dir("app")
                .exit_code(101);
    }
    "closure_call_graph" => {
        closure_call_graph_diagnostics => Case::new("closure diagnostics")
            .args(&["--manifest", "basic.toml"])
            .exit_code(101);
    }
    "indirect_calls" => {
        indirect_call_boundary_diagnostics => Case::new("indirect call boundary diagnostics");
    }
    "trusted_boundaries" => {
        trusted_boundary_diagnostics => Case::new("trusted boundary diagnostics");
    }
    "safety_requirements" => {
        safety_diagnostics => Case::new("safety diagnostics");
        safety_obligation_diagnostics => Case::new("safety obligation diagnostics")
            .args(&["--manifest", "obligations.toml"]);
    }
    "panic_axioms" => {
        compiler_assert_diagnostics => Case::new("compiler assert diagnostics").exit_code(101);
        compiler_assert_division_override_uses_umbrella_fallback =>
            Case::new("division assert override with umbrella fallback")
                .config_append(
                    "\n[panics.lints]\n\
                     compiler-assert-division-by-zero = \"deny\"\n\
                     compiler-assert = \"allow\"\n\
                     panic-invocation = \"allow\"\n",
                )
                .exit_code(101);
        compiler_assert_overrides_are_independent =>
            Case::new("remainder and bounds assert overrides")
                .config_append(
                    "\n[panics.lints]\n\
                     compiler-assert = \"allow\"\n\
                     compiler-assert-remainder-by-zero = \"warn\"\n\
                     compiler-assert-bounds-check = \"deny\"\n\
                     panic-invocation = \"allow\"\n",
                )
                .exit_code(101);
        cargo_manifest_path_forwarding => Case::new("cargo manifest-path forwarding")
            .working_dir("..")
            .args(&["--", "--manifest-path", "{fixture}/Cargo.toml"])
            .exit_code(101);
        config_found_from_subdirectory => Case::new("config discovered from a subdirectory")
            .working_dir("src")
            .exit_code(101);
        rustflags_env_does_not_disable_analysis => Case::new("user RUSTFLAGS coexist")
            .envs(&[("RUSTFLAGS", "--cfg sniff_test_cli_user_flag")])
            .exit_code(101);
    }
    "report_roots" => {
        missing_report_root_diagnostic => Case::new("missing report root diagnostic")
            .args(&["--manifest", "explicit.toml"])
            .exit_code(101);
        missing_report_root_can_be_allowed => Case::new("missing report root allow policy")
            .args(&["--manifest", "allow-missing.toml"]);
        missing_report_root_can_be_denied => Case::new("missing report root deny policy")
            .args(&["--manifest", "deny-missing.toml"])
            .exit_code(101);
        empty_report_roots_can_be_denied => Case::new("empty report roots deny policy")
            .args(&["--manifest", "deny-empty.toml"])
            .exit_code(101);
    }
    "unsafe_ops" => {
        unsafe_op_missing_justification_can_be_denied => Case::new("unsafe operation deny policy")
            .config_append("\n[safety.lints]\nunsafe-op-missing-justification = \"deny\"\n")
            .exit_code(101);
        unsafe_op_overrides_use_umbrella_fallback =>
            Case::new("unsafe operation overrides with umbrella fallback")
                .config_append(
                    "\n[safety.lints]\n\
                     raw-pointer-dereference-missing-justification = \"warn\"\n\
                     unsafe-op-missing-justification = \"allow\"\n\
                     inline-assembly-missing-justification = \"deny\"\n",
                )
                .exit_code(101);
    }
    "ambiguous_markers" => {
        clean_explicit_report_roots_do_not_warn => Case::new("clean explicit report roots")
            .args(&["--manifest", "clean.toml"]);
        ambiguous_marker_diagnostics => Case::new("ambiguous marker diagnostics")
            .args(&["--manifest", "strict.toml"])
            .exit_code(101);
    }
    "ambiguous_safety" => {
        ambiguous_safety_diagnostics => Case::new("ambiguous safety diagnostics").exit_code(101);
        ambiguous_safety_macro_shared_diagnostics =>
            Case::new("shared macro safety marker diagnostics")
                .args(&["--manifest", "macro-shared.toml"])
                .exit_code(101);
    }
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
    let mut command = Command::new(binary);
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
        .args(["--sysroot", rustc_sysroot().trim(), "-Zno-codegen"])
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
        .args(["--sysroot", rustc_sysroot().trim(), "-Zno-codegen"])
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
fn direct_dependency_unit_silently_caches_complete_policy_neutral_v13_ir() {
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
"#,
    )
    .expect("write dependency source");
    let cache_dir = temp.path().join("cache");
    let output = run_dependency_unit(
        temp.path(),
        &cache_dir,
        "artifact_ir_dependency",
        &source,
        None,
        "json",
        &["-Zno-codegen"],
    );
    assert_silent_success(&output, "dependency unit");

    let cache_path = cache_dir
        .join("artifacts")
        .join("artifact_ir_dependency.json");
    let serialized = fs::read_to_string(&cache_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", cache_path.display()));
    let cache: serde_json::Value =
        serde_json::from_str(&serialized).expect("cache should contain JSON");
    assert_eq!(cache["format-version"], 13);
    assert_eq!(cache["artifact"]["crate-name"], "artifact_ir_dependency");

    let functions = cache["ir"]["functions"]
        .as_array()
        .expect("artifact IR functions should be an array");
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
            "artifact IR omitted {expected_name}; cached paths: {display_paths:#?}"
        );
    }
    assert!(
        functions.iter().any(|function| {
            function["display-path"]
                .as_str()
                .is_some_and(|path| path.ends_with("::unreachable_private_helper"))
                && function["effects"]
                    .as_array()
                    .is_some_and(|effects| !effects.is_empty())
        }),
        "artifact IR omitted the private helper's raw compiler-assert effect"
    );

    assert_json_keys_absent(
        &cache,
        &[
            "finding", "findings", "scope", "trace", "traces", "policy", "policies",
        ],
    );
}

#[test]
fn workspace_lint_policy_reinterprets_unchanged_dependency_v13_ir() {
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

    let dependency_cache = fixture
        .cache_dir
        .join("artifacts")
        .join("policy_dependency.json");
    let initial_bytes = fs::read(&dependency_cache)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", dependency_cache.display()));
    let initial_document: serde_json::Value =
        serde_json::from_slice(&initial_bytes).expect("dependency cache should contain JSON");
    assert_eq!(initial_document["format-version"], 13);
    let analysis_id_before = initial_document["analysis-id"]
        .as_str()
        .expect("dependency cache should have an analysis id")
        .to_owned();
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
    let final_document: serde_json::Value =
        serde_json::from_slice(&final_bytes).expect("dependency cache should remain valid JSON");
    assert_eq!(final_document["analysis-id"], analysis_id_before);
    assert_eq!(
        final_bytes, initial_bytes,
        "lint-only workspace runs must not rewrite dependency IR"
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
    // the v13 sidecar deliberately describes the previous crate metadata.
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
        .args(["--sysroot", sysroot.trim()])
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
        stderr.contains("does not match rustc's loaded crate identity"),
        "stderr:\n{stderr}"
    );
    assert_eq!(
        stderr
            .matches("does not match rustc's loaded crate identity")
            .count(),
        1,
        "identity mismatch should be reported once\nstderr:\n{stderr}"
    );
}

#[test]
fn unused_dependency_ir_produces_no_workspace_findings() {
    let temp = tempfile::tempdir().expect("temp dir");
    let dependency_source = temp.path().join("unused_ir_dependency.rs");
    fs::write(
        &dependency_source,
        "pub fn unreachable_dependency_panic() { panic!(\"unused\") }\n",
    )
    .expect("write dependency source");
    let dependency_rlib = temp.path().join("libunused_ir_dependency.rlib");
    let cache_dir = temp.path().join("cache");
    let driver = PathBuf::from(env!("CARGO_BIN_EXE_sniff-test-driver"));
    let sysroot = rustc_sysroot();
    let mut dependency = Command::new(&driver);
    clean_cargo_package_env(&mut dependency);
    let dependency_output = dependency
        .arg("--dependency")
        .args(["--cache-dir"])
        .arg(&cache_dir)
        .args(["--message-format", "json", "--color", "never", "--"])
        .args([
            "--crate-name",
            "unused_ir_dependency",
            "--crate-type",
            "rlib",
            "--edition",
            "2024",
        ])
        .arg(&dependency_source)
        .arg("-o")
        .arg(&dependency_rlib)
        .args(["--sysroot", sysroot.trim()])
        .current_dir(temp.path())
        .output()
        .expect("compile dependency");
    assert!(
        dependency_output.status.success()
            && dependency_output.stdout.is_empty()
            && dependency_output.stderr.is_empty(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&dependency_output.stdout),
        String::from_utf8_lossy(&dependency_output.stderr)
    );

    let workspace_source = temp.path().join("unused_ir_workspace.rs");
    fs::write(&workspace_source, "pub fn workspace_root() {}\n").expect("write workspace source");
    let manifest = temp.path().join("sniff-test.toml");
    fs::write(
        &manifest,
        "[analysis]\nreport-roots = [\"unused_ir_workspace::workspace_root\"]\n",
    )
    .expect("write manifest");
    let mut workspace = Command::new(&driver);
    clean_cargo_package_env(&mut workspace);
    let output = workspace
        .args(["--manifest"])
        .arg(&manifest)
        .args(["--cache-dir"])
        .arg(&cache_dir)
        .args(["--message-format", "json", "--color", "never", "--"])
        .args([
            "--crate-name",
            "unused_ir_workspace",
            "--crate-type",
            "lib",
            "--edition",
            "2024",
        ])
        .arg(&workspace_source)
        .arg("-L")
        .arg(temp.path())
        .arg("--extern")
        .arg("unused_ir_dependency")
        .args(["--sysroot", sysroot.trim(), "-Zno-codegen"])
        .env("CARGO_PRIMARY_PACKAGE", "1")
        .current_dir(temp.path())
        .output()
        .expect("analyze workspace");

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
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
    assert!(
        unavailable_stderr
            .lines()
            .all(|line| !line.trim_start().starts_with("-->")),
        "a finding with unavailable cached source must be unspanned:\n{unavailable_stderr}"
    );
}

#[test]
fn workspace_unit_fails_when_required_extern_artifact_ir_is_missing() {
    let temp = tempfile::tempdir().expect("temp dir");
    let dependency_source = temp.path().join("required_ir_dep.rs");
    fs::write(&dependency_source, "pub fn dependency_body() {}\n")
        .expect("write dependency source");
    let dependency_rlib = temp.path().join("librequired_ir_dep.rlib");
    let cache_dir = temp.path().join("cache");
    let driver = PathBuf::from(env!("CARGO_BIN_EXE_sniff-test-driver"));

    let mut dependency_command = Command::new(&driver);
    clean_cargo_package_env(&mut dependency_command);
    let dependency_output = dependency_command
        .arg("--dependency")
        .args(["--cache-dir"])
        .arg(&cache_dir)
        .args(["--message-format", "json", "--color", "never", "--"])
        .args([
            "--crate-name",
            "required_ir_dep",
            "--crate-type",
            "rlib",
            "--edition",
            "2024",
        ])
        .arg(&dependency_source)
        .arg("-o")
        .arg(&dependency_rlib)
        .args(["--sysroot", rustc_sysroot().trim()])
        .current_dir(temp.path())
        .output()
        .expect("compile dependency rustc unit");
    assert!(
        dependency_output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&dependency_output.stdout),
        String::from_utf8_lossy(&dependency_output.stderr)
    );
    assert!(dependency_rlib.is_file(), "dependency rlib was not written");

    let dependency_cache = cache_dir.join("artifacts").join("required_ir_dep.json");
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
        .args(["--sysroot", rustc_sysroot().trim(), "-Zno-codegen"])
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
        stderr.contains("error: failed to load required dependency artifact IR"),
        "stderr:\n{stderr}"
    );
    assert_eq!(
        stderr
            .matches("failed to load required dependency artifact IR")
            .count(),
        1,
        "missing required IR should emit exactly one tool error\nstderr:\n{stderr}"
    );
}

#[test]
fn cargo_frontend_fails_when_dependency_analysis_cannot_be_cached() {
    let temp = tempfile::tempdir().expect("temp dir");
    let fixture = temp.path().join("dependency_identity");
    copy_dir_all(
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
fn direct_driver_fails_when_required_artifact_ir_cannot_be_cached() {
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
        .args(["--sysroot", rustc_sysroot().trim(), "-Zno-codegen"])
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
    let path_context = stderr
        .find(&format!("failed to parse {}", manifest.display()))
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
        .args(["--sysroot", rustc_sysroot().trim(), "-Zno-codegen"])
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
        .args(["--sysroot", rustc_sysroot().trim(), "-Zno-codegen"])
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
        .args(["--sysroot", rustc_sysroot().trim()])
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
        .args(["--sysroot", rustc_sysroot().trim(), "-Zno-codegen"])
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
    const fn new(behavior: &'static str) -> Self {
        Self {
            behavior,
            expected_exit: 0,
            crate_dir: "",
            working_dir: None,
            config_append: "",
            args: &[],
            envs: &[],
        }
    }

    const fn exit_code(mut self, exit_code: i32) -> Self {
        self.expected_exit = exit_code;
        self
    }

    const fn crate_dir(mut self, crate_dir: &'static str) -> Self {
        self.crate_dir = crate_dir;
        self
    }

    const fn working_dir(mut self, working_dir: &'static str) -> Self {
        self.working_dir = Some(working_dir);
        self
    }

    const fn config_append(mut self, config_append: &'static str) -> Self {
        self.config_append = config_append;
        self
    }

    const fn args(mut self, args: &'static [&'static str]) -> Self {
        self.args = args;
        self
    }

    const fn envs(mut self, envs: &'static [(&'static str, &'static str)]) -> Self {
        self.envs = envs;
        self
    }
}

fn run_named_case(name: &'static str, fixture_name: &'static str, case: Case) {
    let repo = repo_root();
    let sysroot = rustc_sysroot();
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_cargo-sniff-test"));
    let (output, fixture_root) = run_case(&repo, &binary, name, fixture_name, &case);

    assert_eq!(
        output.status.code(),
        Some(case.expected_exit),
        "{} ({}/{}): command exited {:?}, expected {}\nstdout:\n{}\nstderr:\n{}",
        name,
        fixture_name,
        case.behavior,
        output.status.code(),
        case.expected_exit,
        output.stdout,
        output.stderr
    );

    let snapshot = render_snapshot(&output, &fixture_root, sysroot.trim());
    insta::assert_snapshot!(name, snapshot);
}

fn run_case(
    repo: &Path,
    binary: &Path,
    name: &str,
    fixture_name: &str,
    case: &Case,
) -> (CommandOutput, PathBuf) {
    let fixture = repo.join("tests/fixtures").join(fixture_name);
    assert!(
        fixture.exists(),
        "{} ({}/{}): missing fixture {}",
        name,
        fixture_name,
        case.behavior,
        fixture.display()
    );

    let temp = tempfile::Builder::new()
        .prefix(&format!("sniff-test-cli-{name}-"))
        .tempdir()
        .unwrap_or_else(|error| panic!("{name}: failed to create temp dir: {error}"));
    let root = temp.path().join(fixture_name);
    copy_dir_all(&fixture, &root)
        .unwrap_or_else(|error| panic!("{name}: failed to copy fixture: {error}"));

    if !case.config_append.is_empty() {
        let config = root.join(case.crate_dir).join("sniff-test.toml");
        let existing = fs::read_to_string(&config)
            .unwrap_or_else(|error| panic!("{name}: failed to read config: {error}"));
        fs::write(config, existing + case.config_append)
            .unwrap_or_else(|error| panic!("{name}: failed to update config: {error}"));
    }

    let working_dir = root.join(case.working_dir.unwrap_or(case.crate_dir));
    let _cargo_guard = lock_nested_cargo();
    let output = run_cargo_sniff_test(binary, &working_dir, &root, name, case);
    (output, root)
}

fn run_cargo_sniff_test(
    binary: &Path,
    working_dir: &Path,
    fixture_root: &Path,
    name: &str,
    case: &Case,
) -> CommandOutput {
    let mut command = Command::new(binary);
    clean_cargo_package_env(&mut command);
    for (key, value) in case.envs {
        command.env(key, value);
    }
    let output = command
        .args(["--color", "never"])
        .args(expand_args(case.args, fixture_root))
        .current_dir(working_dir)
        .output()
        .unwrap_or_else(|error| panic!("{name}: failed to run {}: {error}", binary.display()));
    CommandOutput::from_output(output)
}

fn expand_args(args: &[&str], fixture_root: &Path) -> Vec<String> {
    let fixture_name = fixture_root
        .file_name()
        .expect("fixture root should have a name")
        .to_string_lossy();
    args.iter()
        .map(|arg| arg.replace("{fixture}", &fixture_name))
        .collect()
}

fn render_snapshot(output: &CommandOutput, fixture_root: &Path, sysroot: &str) -> String {
    let mut rendered = String::new();
    writeln!(
        &mut rendered,
        "exit: {}",
        output.status.code().unwrap_or(-1)
    )
    .unwrap();
    writeln!(&mut rendered, "stdout:").unwrap();
    rendered.push_str(&snapshot_section(&output.stdout, fixture_root, sysroot));
    writeln!(&mut rendered, "stderr:").unwrap();
    rendered.push_str(&snapshot_section(&output.stderr, fixture_root, sysroot));
    rendered
}

fn snapshot_section(text: &str, fixture_root: &Path, sysroot: &str) -> String {
    if text.is_empty() {
        return String::from("<empty>\n");
    }

    let normalized = normalize_output(text, fixture_root, sysroot);
    if normalized.is_empty() {
        return String::from("<empty>\n");
    }

    let mut section = String::new();
    for line in normalized.lines() {
        writeln!(&mut section, "{line}").unwrap();
    }
    section
}

fn normalize_output(text: &str, fixture_root: &Path, sysroot: &str) -> String {
    text.lines()
        .map(|line| normalize_line(line, fixture_root, sysroot))
        .filter(|line| !is_volatile_cargo_status(line))
        .collect::<Vec<_>>()
        .join("\n")
}

fn normalize_line(line: &str, fixture_root: &Path, sysroot: &str) -> String {
    let mut line = line
        .replace(&fixture_root.display().to_string(), "[FIXTURE]")
        .replace(sysroot, "[SYSROOT]");
    // Cases running from the temp dir itself leak its per-run name, such as
    // the config-discovery notice.
    if let Some(parent) = fixture_root.parent() {
        line = line.replace(&parent.display().to_string(), "[TEMP]");
    }

    if let Some((prefix, _time)) = line.split_once(" target(s) in ") {
        line = format!("{prefix} target(s) in [TIME]");
    }

    line
}

fn is_volatile_cargo_status(line: &str) -> bool {
    let line = line.trim_start();
    line.starts_with("Locking ")
        && line.contains(" package")
        && line.contains(" compatible version")
}

fn assert_json_keys_absent(value: &serde_json::Value, forbidden: &[&str]) {
    match value {
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                assert!(
                    !forbidden.contains(&key.as_str()),
                    "serialized artifact IR contains forbidden `{key}` field"
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
