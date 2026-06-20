use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cases {
    case: Vec<Case>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    fixture: String,
    #[serde(default)]
    driver: Driver,
    #[serde(default)]
    crate_dir: PathBuf,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    exit_code: i32,
    crate_name: Option<String>,
    crate_type: Option<String>,
    edition: Option<String>,
    source: Option<PathBuf>,
    manifest: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Driver {
    #[default]
    Cargo,
    Direct,
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

#[test]
fn json_fixtures() {
    let repo = repo_root();
    let cases = load_cases(&repo);
    let binaries = Binaries::from_cargo();
    let sysroot = rustc_sysroot();

    let mut settings = insta::Settings::clone_current();
    settings.set_snapshot_path(repo.join("tests/snapshots"));

    settings.bind(|| {
        for case in cases {
            let messages = run_case(&repo, &binaries, &sysroot, &case);
            insta::assert_json_snapshot!(case.name, messages);
        }
    });
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

fn load_cases(repo: &Path) -> Vec<Case> {
    let cases_path = repo.join("tests/cases.toml");
    let cases = fs::read_to_string(&cases_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", cases_path.display()));
    toml::from_str::<Cases>(&cases)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", cases_path.display()))
        .case
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

fn run_case(repo: &Path, binaries: &Binaries, sysroot: &str, case: &Case) -> Vec<Value> {
    let fixture = repo.join("tests/fixtures").join(&case.fixture);
    assert!(
        fixture.exists(),
        "{}: missing fixture {}",
        case.name,
        fixture.display()
    );

    let temp = tempfile::Builder::new()
        .prefix(&format!("sniff-test-{}-", case.name))
        .tempdir()
        .unwrap_or_else(|error| panic!("{}: failed to create temp dir: {error}", case.name));
    let root = temp.path().join(&case.fixture);
    copy_dir_all(&fixture, &root)
        .unwrap_or_else(|error| panic!("{}: failed to copy fixture: {error}", case.name));

    let output = if case.driver == Driver::Direct {
        run_direct_driver_case(&binaries.driver, sysroot, &root, case)
    } else {
        run_cargo_case(&binaries.cargo, &root, case)
    };
    assert_eq!(
        output.status.code(),
        Some(case.exit_code),
        "{}: command exited {:?}, expected {}\nstdout:\n{}\nstderr:\n{}",
        case.name,
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
                panic!("{}: invalid JSON line: {error}\n{line}", case.name)
            });
            normalize_json(&mut value, &root, sysroot.trim());
            value
        })
        .collect::<Vec<_>>();
    assert!(
        !messages.is_empty(),
        "{}: no JSON messages emitted",
        case.name
    );

    messages.sort_by_key(message_sort_key);
    messages
}

fn run_cargo_case(binary: &Path, root: &Path, case: &Case) -> CommandOutput {
    let crate_dir = root.join(&case.crate_dir);
    let mut command = Command::new(binary);
    clean_cargo_package_env(&mut command);
    let output = command
        .args(["--message-format", "json", "--color", "never", "--release"])
        .args(&case.args)
        .current_dir(crate_dir)
        .output()
        .unwrap_or_else(|error| {
            panic!("{}: failed to run {}: {error}", case.name, binary.display())
        });
    CommandOutput::from_output(output)
}

fn run_direct_driver_case(binary: &Path, sysroot: &str, root: &Path, case: &Case) -> CommandOutput {
    let source = root.join(
        case.source
            .as_deref()
            .unwrap_or_else(|| Path::new("src/lib.rs")),
    );
    let manifest = root.join(
        case.manifest
            .as_deref()
            .unwrap_or_else(|| Path::new("sniff-test.toml")),
    );
    let crate_name = case.crate_name.clone().unwrap_or_else(|| {
        root.file_name()
            .unwrap()
            .to_string_lossy()
            .replace('-', "_")
    });
    let crate_type = case.crate_type.as_deref().unwrap_or("lib");
    let edition = case.edition.as_deref().unwrap_or("2024");

    let mut command = Command::new(binary);
    clean_cargo_package_env(&mut command);
    let output = command
        .args(["--crate-name", &crate_name])
        .args(["--crate-type", crate_type])
        .args(["--edition", edition])
        .arg(source)
        .args(["--sysroot", sysroot.trim(), "-Zno-codegen", "--"])
        .args(["--manifest"])
        .arg(manifest)
        .args(["--message-format", "json", "--color", "never"])
        .args(&case.args)
        .env("CARGO_PRIMARY_PACKAGE", "1")
        .current_dir(root)
        .output()
        .unwrap_or_else(|error| {
            panic!("{}: failed to run {}: {error}", case.name, binary.display())
        });
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
