use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::{LazyLock, Mutex};

static CASE_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

#[derive(Clone, Copy, Debug)]
struct Case {
    behavior: &'static str,
    expected_exit: i32,
    crate_dir: &'static str,
    working_dir: Option<&'static str>,
    config_append: &'static str,
    args: &'static [&'static str],
}

struct CommandOutput {
    status: ExitStatus,
    stdout: String,
    stderr: String,
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
    "safe_markers" => {
        compact_stack_hint => Case::new("compact stack hint").exit_code(1);
        full_stack_trace => Case::new("full stack trace")
            .exit_code(1)
            .config_append("\nshow-full-stack-trace = true\n");
    }
    "dependency_obligation" => {
        dependency_warning_footer => Case::new("dependency warning footer").crate_dir("app");
    }
    "safety_requirements" => {
        safety_diagnostics => Case::new("safety diagnostics");
    }
    "panic_axioms" => {
        compiler_assert_diagnostics => Case::new("compiler assert diagnostics").exit_code(1);
        cargo_manifest_path_forwarding => Case::new("cargo manifest-path forwarding")
            .working_dir("..")
            .args(&["--", "--manifest-path", "{fixture}/Cargo.toml"])
            .exit_code(1);
    }
    "report_roots" => {
        missing_report_root_diagnostic => Case::new("missing report root diagnostic")
            .args(&["--manifest", "explicit.toml"])
            .exit_code(1);
    }
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
}

fn run_named_case(name: &'static str, fixture_name: &'static str, case: Case) {
    let _guard = CASE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

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
    let mut section = String::new();
    for line in normalized.lines() {
        writeln!(&mut section, "{line}").unwrap();
    }
    section
}

fn normalize_output(text: &str, fixture_root: &Path, sysroot: &str) -> String {
    text.lines()
        .map(|line| normalize_line(line, fixture_root, sysroot))
        .collect::<Vec<_>>()
        .join("\n")
}

fn normalize_line(line: &str, fixture_root: &Path, sysroot: &str) -> String {
    let mut line = line
        .replace(&fixture_root.display().to_string(), "[FIXTURE]")
        .replace(sysroot, "[SYSROOT]");

    if let Some((prefix, _time)) = line.split_once(" target(s) in ") {
        line = format!("{prefix} target(s) in [TIME]");
    }

    line
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
