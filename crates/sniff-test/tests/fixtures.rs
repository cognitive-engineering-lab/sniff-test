use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::{LazyLock, Mutex};

use serde_json::Value;

static CASE_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

#[derive(Clone, Copy, Debug)]
struct Case {
    behavior: &'static str,
    driver: Driver,
    crate_dir: &'static str,
    args: &'static [&'static str],
    exit_code: i32,
    crate_type: &'static str,
    edition: &'static str,
    source: &'static str,
    manifest: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Driver {
    Cargo,
    Direct,
}

impl Case {
    #[must_use]
    const fn cargo(behavior: &'static str) -> Self {
        Self {
            behavior,
            driver: Driver::Cargo,
            crate_dir: "",
            args: &[],
            exit_code: 0,
            crate_type: "lib",
            edition: "2024",
            source: "src/lib.rs",
            manifest: "sniff-test.toml",
        }
    }

    #[must_use]
    const fn direct(behavior: &'static str) -> Self {
        Self {
            driver: Driver::Direct,
            ..Self::cargo(behavior)
        }
    }

    #[must_use]
    const fn crate_dir(mut self, crate_dir: &'static str) -> Self {
        self.crate_dir = crate_dir;
        self
    }

    #[must_use]
    const fn args(mut self, args: &'static [&'static str]) -> Self {
        self.args = args;
        self
    }

    #[must_use]
    const fn exit_code(mut self, exit_code: i32) -> Self {
        self.exit_code = exit_code;
        self
    }

    #[must_use]
    const fn manifest(mut self, manifest: &'static str) -> Self {
        self.manifest = manifest;
        self
    }
}

struct Binaries {
    cargo: PathBuf,
    driver: PathBuf,
}

struct CommandOutput {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

macro_rules! fixture_cases {
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

fixture_cases! {
    "panic_axioms" => {
        panic_axioms => Case::cargo("raw panic paths").exit_code(1);
        driver_panic_axioms => Case::direct("raw panic paths");
    }
    "generic_roots" => {
        generic_roots => Case::cargo("generic roots").exit_code(1);
        driver_generic_roots => Case::direct("generic roots");
    }
    "direct_panic" => {
        direct_panic => Case::cargo("direct panic").exit_code(1);
        driver_direct_panic => Case::direct("direct panic");
    }
    "closure_call_graph" => {
        closure_call_graph => Case::cargo("call graph edges").exit_code(1);
        driver_closure_call_graph => Case::direct("call graph edges");
    }
    "custom_index_impl" => {
        custom_index_impl => Case::cargo("custom index dispatch").exit_code(1);
        driver_custom_index_impl => Case::direct("custom index dispatch");
    }
    "trait_default_method" => {
        trait_default_method => Case::cargo("trait default dispatch").exit_code(1);
        driver_trait_default_method => Case::direct("trait default dispatch");
    }
    "dyn_dispatch_call_site" => {
        dyn_dispatch_call_site => Case::cargo("dyn dispatch call-site attribution").exit_code(1);
        driver_dyn_dispatch_call_site => Case::direct("dyn dispatch call-site attribution");
    }
    "dyn_dispatch_same_trait" => {
        dyn_dispatch_same_trait => Case::cargo("dyn dispatch same-trait approximation").exit_code(1);
        driver_dyn_dispatch_same_trait => Case::direct("dyn dispatch same-trait approximation");
    }
    "documented_obligation" => {
        documented_obligation => Case::cargo("documented panic obligation").exit_code(1);
        documented_obligation_allowed => Case::cargo("allowed documented panic obligation")
            .args(&["--manifest", "allow.toml"]);
        driver_documented_obligation => Case::direct("documented panic obligation");
        driver_documented_obligation_allowed => Case::direct("allowed documented panic obligation")
            .manifest("allow.toml");
    }
    "release_pruning" => {
        release_pruning => Case::cargo("release profile pruning").exit_code(1);
    }
    "optimizer_pruning" => {
        optimizer_pruning => Case::cargo("optimizer pruning");
    }
    "feature_gated" => {
        feature_gated => Case::cargo("feature-enabled raw panic")
            .args(&["--", "--features", "dangerous"])
            .exit_code(1);
        feature_gated_default => Case::cargo("feature-default clean");
    }
    "suppression" => {
        suppression => Case::cargo("suppressed");
        suppression_miss => Case::cargo("suppression miss")
            .args(&["--manifest", "miss.toml"])
            .exit_code(1);
        driver_suppression => Case::direct("suppressed");
        driver_suppression_miss => Case::direct("suppression miss").manifest("miss.toml");
    }
    "dependency_obligation" => {
        dependency_obligation => Case::cargo("dependency obligation").crate_dir("app");
        dependency_obligation_relative_cache => Case::cargo("relative dependency cache")
            .crate_dir("app")
            .args(&["--cache-dir", ".sniff-cache"]);
    }
    "safe_markers" => {
        safe_markers => Case::cargo("panic marker satisfaction").exit_code(1);
        driver_safe_markers => Case::direct("panic marker satisfaction");
    }
    "panic_requirements" => {
        panic_requirements => Case::cargo("panic requirement satisfaction");
        driver_panic_requirements => Case::direct("panic requirement satisfaction");
    }
    "safety_requirements" => {
        safety_requirements => Case::cargo("safety requirement satisfaction");
        safety_requirements_allowed => Case::cargo("allowed safety findings")
            .args(&["--manifest", "allow.toml"]);
        safety_requirements_denied => Case::cargo("denied safety finding")
            .args(&["--manifest", "deny.toml"])
            .exit_code(1);
        safety_requirements_ignored => Case::cargo("ignored safety namespaces")
            .args(&["--manifest", "ignore.toml"]);
        safety_requirements_obligations => Case::cargo("configured safety obligations")
            .args(&["--manifest", "obligations.toml"]);
        driver_safety_requirements => Case::direct("safety requirement satisfaction");
    }
    "marker_placement" => {
        marker_placement => Case::cargo("marker placement").exit_code(1);
        driver_marker_placement => Case::direct("marker placement");
    }
    "trusted_boundaries" => {
        trusted_boundaries => Case::cargo("trusted boundary");
        trusted_boundaries_untrusted => Case::cargo("untrusted boundary")
            .args(&["--manifest", "untrusted.toml"])
            .exit_code(1);
        driver_trusted_boundaries => Case::direct("trusted boundary");
        driver_trusted_boundaries_untrusted => Case::direct("untrusted boundary")
            .manifest("untrusted.toml");
    }
    "report_roots" => {
        report_roots_public => Case::cargo("public report roots").exit_code(1);
        report_roots_all => Case::cargo("all report roots")
            .args(&["--manifest", "all.toml"])
            .exit_code(1);
        report_roots_explicit => Case::cargo("explicit report roots")
            .args(&["--manifest", "explicit.toml"])
            .exit_code(1);
        driver_report_roots_public => Case::direct("public report roots");
        driver_report_roots_all => Case::direct("all report roots").manifest("all.toml");
        driver_report_roots_explicit => Case::direct("explicit report roots").manifest("explicit.toml");
    }
    "direct_driver_panic" => {
        direct_driver_panic => Case::direct("direct driver raw panic");
    }
    "direct_driver_safe" => {
        direct_driver_safe => Case::direct("direct driver clean");
    }
}

fn run_named_case(name: &'static str, fixture_name: &'static str, case: Case) {
    let _guard = CASE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let repo = repo_root();
    let binaries = Binaries::from_cargo();
    let sysroot = rustc_sysroot();
    let messages = run_case(&repo, &binaries, &sysroot, name, fixture_name, &case);
    insta::assert_json_snapshot!(name, messages);
}

impl Binaries {
    fn from_cargo() -> Self {
        Self {
            cargo: PathBuf::from(env!("CARGO_BIN_EXE_cargo-sniff-test")),
            driver: PathBuf::from(env!("CARGO_BIN_EXE_sniff-test-driver")),
        }
    }
}

fn repo_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("sniff-test crate should live under crates/sniff-test")
        .to_path_buf()
}

fn rustc_sysroot() -> String {
    let rustc = std::env::var_os("RUSTC").map_or_else(|| PathBuf::from("rustc"), PathBuf::from);
    let output = Command::new(&rustc)
        .args(["--print", "sysroot"])
        .output()
        .unwrap_or_else(|error| {
            panic!("failed to run {} --print sysroot: {error}", rustc.display())
        });

    assert!(
        output.status.success(),
        "{}",
        command_failure(&rustc.display().to_string(), &output)
    );

    String::from_utf8(output.stdout).expect("rustc sysroot output should be utf-8")
}

fn run_case(
    repo: &Path,
    binaries: &Binaries,
    sysroot: &str,
    name: &str,
    fixture_name: &str,
    case: &Case,
) -> Vec<Value> {
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
        .prefix(&format!("sniff-test-{name}-"))
        .tempdir()
        .unwrap_or_else(|error| panic!("{name}: failed to create temp dir: {error}"));
    let root = temp.path().join(fixture_name);
    copy_dir_all(&fixture, &root)
        .unwrap_or_else(|error| panic!("{name}: failed to copy fixture: {error}"));

    let output = if case.driver == Driver::Direct {
        run_direct_driver_case(&binaries.driver, sysroot, &root, name, fixture_name, case)
    } else {
        run_cargo_case(&binaries.cargo, &root, name, case)
    };
    assert_eq!(
        output.status.code(),
        Some(case.exit_code),
        "{} ({}/{}): command exited {:?}, expected {}\nstdout:\n{}\nstderr:\n{}",
        name,
        fixture_name,
        case.behavior,
        output.status.code(),
        case.exit_code,
        output.stdout,
        output.stderr
    );

    let mut messages = output
        .stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let mut value = serde_json::from_str::<Value>(line).unwrap_or_else(|error| {
                panic!(
                    "{} ({}/{}): invalid JSON line: {error}\n{line}",
                    name, fixture_name, case.behavior
                )
            });
            normalize_json(&mut value, &root, sysroot.trim());
            value
        })
        .collect::<Vec<_>>();
    assert!(
        !messages.is_empty(),
        "{} ({}/{}): no JSON messages emitted",
        name,
        fixture_name,
        case.behavior
    );

    messages.sort_by_key(message_sort_key);
    messages
}

fn run_cargo_case(binary: &Path, root: &Path, name: &str, case: &Case) -> CommandOutput {
    let crate_dir = root.join(case.crate_dir);
    let mut command = Command::new(binary);
    clean_cargo_package_env(&mut command);
    let output = command
        .args(["--message-format", "json", "--color", "never", "--release"])
        .args(case.args)
        .current_dir(crate_dir)
        .output()
        .unwrap_or_else(|error| panic!("{name}: failed to run {}: {error}", binary.display()));
    CommandOutput::from_output(output)
}

fn run_direct_driver_case(
    binary: &Path,
    sysroot: &str,
    root: &Path,
    name: &str,
    fixture_name: &str,
    case: &Case,
) -> CommandOutput {
    let source = root.join(case.source);
    let manifest = root.join(case.manifest);
    let crate_name = fixture_name.replace('-', "_");
    let crate_type = case.crate_type;
    let edition = case.edition;

    let mut command = Command::new(binary);
    clean_cargo_package_env(&mut command);
    let output = command
        .args(["--crate-name", crate_name.as_str()])
        .args(["--crate-type", crate_type])
        .args(["--edition", edition])
        .arg(source)
        .args(["--sysroot", sysroot.trim(), "-Zno-codegen", "--"])
        .args(["--manifest"])
        .arg(manifest)
        .args(["--message-format", "json", "--color", "never"])
        .args(case.args)
        .env("CARGO_PRIMARY_PACKAGE", "1")
        .current_dir(root)
        .output()
        .unwrap_or_else(|error| panic!("{name}: failed to run {}: {error}", binary.display()));
    CommandOutput::from_output(output)
}

fn clean_cargo_package_env(command: &mut Command) {
    command
        .env_remove("CARGO_MANIFEST_PATH")
        .env_remove("CARGO_PRIMARY_PACKAGE")
        .env_remove("CARGO_PKG_NAME")
        .env_remove("CARGO_PKG_VERSION");
}

impl CommandOutput {
    fn from_output(output: std::process::Output) -> Self {
        Self {
            status: output.status,
            stdout: String::from_utf8(output.stdout).expect("stdout should be utf-8"),
            stderr: String::from_utf8(output.stderr).expect("stderr should be utf-8"),
        }
    }
}

fn normalize_json(value: &mut Value, fixture_root: &Path, sysroot: &str) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if volatile_key(key) {
                    *value =
                        Value::String(format!("[{}]", key.to_ascii_uppercase().replace('-', "_")));
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

fn volatile_key(key: &str) -> bool {
    matches!(
        key,
        "artifact-id"
            | "artifact-path"
            | "exact-cache-path"
            | "rustc-version"
            | "metadata"
            | "extra-filename"
    )
}

fn message_sort_key(message: &Value) -> (String, String, String) {
    let artifact = message.get("artifact").unwrap_or(&Value::Null);
    (
        json_string(message, "reason"),
        json_string(artifact, "crate-name"),
        json_string(message, "scope"),
    )
}

fn json_string(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn copy_dir_all(source: &Path, destination: &Path) -> io::Result<()> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if kind.is_dir() {
            copy_dir_all(&source_path, &destination_path)?;
        } else {
            fs::copy(source_path, destination_path)?;
        }
    }
    Ok(())
}

fn command_failure(command: &str, output: &std::process::Output) -> String {
    format!(
        "command failed: {command}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
