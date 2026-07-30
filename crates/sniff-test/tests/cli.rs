mod common;

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

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
fn direct_driver_reports_linked_rustc_version() {
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
        .args(["--color", "never", "--release"])
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
fn direct_driver_warns_when_analysis_cache_write_fails() {
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
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("warning: failed to write analysis cache"),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
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
fn invalid_cargo_manifest_is_rendered_by_driver_boundary() {
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

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.starts_with("error: failed to determine crate output scope\n\nCaused by:\n    "),
        "stderr: {stderr}"
    );
    assert!(stderr.contains(&cargo_manifest.display().to_string()));
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
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Usage: cargo sniff-test"),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
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
        .args(["--color", "never", "--release"])
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
