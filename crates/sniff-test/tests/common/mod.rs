//! Helpers shared by the cli and fixtures harnesses.

use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::{Mutex, MutexGuard};

static NESTED_CARGO_LOCK: Mutex<()> = Mutex::new(());

pub const COMPILER_DEBUG_FRAGMENTS: &[&str] = &[
    "copy _",
    "move _",
    " with locals ",
    "CompilerAssertLocal {",
    "Binder {",
    "bound_vars:",
    "BoundsCheck {",
    "Overflow(",
    "OverflowNeg(",
    "DivisionByZero(",
    "RemainderByZero(",
    "ResumedAfterReturn(",
    "ResumedAfterPanic(",
    "ResumedAfterDrop(",
    "MisalignedPointerDereference {",
    "NullPointerDereference",
    "InvalidEnumConstruction(",
];

pub struct CommandOutput {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

impl CommandOutput {
    pub fn from_output(output: std::process::Output) -> Self {
        Self {
            status: output.status,
            stdout: String::from_utf8(output.stdout).expect("stdout should be utf-8"),
            stderr: String::from_utf8(output.stderr).expect("stderr should be utf-8"),
        }
    }
}

pub fn repo_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("sniff-test crate should live under crates/sniff-test")
        .to_path_buf()
}

pub fn rustc_sysroot() -> String {
    let rustc = std::env::var_os("RUSTC").map_or_else(|| PathBuf::from("rustc"), PathBuf::from);
    let output = Command::new(&rustc)
        .args(["--print", "sysroot"])
        .output()
        .unwrap_or_else(|error| {
            panic!("failed to run {} --print sysroot: {error}", rustc.display())
        });

    assert!(
        output.status.success(),
        "command failed: {} --print sysroot\nstdout:\n{}\nstderr:\n{}",
        rustc.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout)
        .expect("rustc sysroot output should be utf-8")
        .trim()
        .to_owned()
}

/// Serializes nested Cargo invocations within one integration-test process.
///
/// The outer test harness may otherwise run several Cargo processes against
/// the same package cache, making volatile file-lock status messages leak into
/// snapshot output.
pub fn lock_nested_cargo() -> MutexGuard<'static, ()> {
    NESTED_CARGO_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Prevent the outer `cargo test` package metadata from leaking into fixture
/// runs; the analyzer uses these vars for scope and artifact metadata.
pub fn clean_cargo_package_env(command: &mut Command) {
    command
        .env_remove("CARGO_MANIFEST_PATH")
        .env_remove("CARGO_PRIMARY_PACKAGE")
        .env_remove("CARGO_PKG_NAME")
        .env_remove("CARGO_PKG_VERSION");
}

pub fn copy_fixture_dir(source: &Path, destination: &Path) -> io::Result<()> {
    fs::create_dir_all(destination)?;
    let has_cargo_manifest = source.join("Cargo.toml").is_file();
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let source_path = entry.path();
        let file_name = entry.file_name();
        if has_cargo_manifest && kind.is_dir() && file_name == "target" {
            continue;
        }
        let destination_path = destination.join(file_name);
        if kind.is_dir() {
            copy_fixture_dir(&source_path, &destination_path)?;
        } else {
            fs::copy(source_path, destination_path)?;
        }
    }
    Ok(())
}

pub fn assert_public_output_uses_human_words(name: &str, output: &str) {
    for fragment in COMPILER_DEBUG_FRAGMENTS {
        assert!(
            !output.contains(fragment),
            "{name}: public diagnostic contains compiler debug output `{fragment}`:\n{output}"
        );
    }
    assert!(
        !output.contains("reachability root"),
        "{name}: public diagnostic contains internal reachability jargon:\n{output}"
    );
}

pub fn render_snapshot(
    status: ExitStatus,
    stdout: &str,
    stderr: &str,
    fixture_root: &Path,
    sysroot: &str,
) -> String {
    let mut rendered = String::new();
    writeln!(&mut rendered, "exit: {}", status.code().unwrap_or(-1)).unwrap();
    writeln!(&mut rendered, "stdout:").unwrap();
    rendered.push_str(&snapshot_section(stdout, fixture_root, sysroot));
    writeln!(&mut rendered, "stderr:").unwrap();
    rendered.push_str(&snapshot_section(stderr, fixture_root, sysroot));
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

pub fn normalize_line(line: &str, fixture_root: &Path, sysroot: &str) -> String {
    let mut line = normalize_path(line, fixture_root, "[FIXTURE]");
    line = normalize_path(&line, Path::new(sysroot), "[SYSROOT]");
    line = normalize_path(
        &line,
        Path::new(env!("CARGO_BIN_EXE_cargo-sniff-test")),
        "[SNIFF-TEST]",
    );
    // Cases running from the temp dir itself leak its per-run name, such as
    // the config-discovery notice.
    if let Some(parent) = fixture_root.parent() {
        line = normalize_path(&line, parent, "[TEMP]");
    }

    if let Some((prefix, _time)) = line.split_once(" target(s) in ") {
        line = format!("{prefix} target(s) in [TIME]");
    }

    normalize_cache_format_version(line)
}

fn normalize_cache_format_version(mut line: String) -> String {
    const MARKER: &str = "sniff-test-cache/v";
    let Some(version_start) = line.find(MARKER).map(|start| start + MARKER.len()) else {
        return line;
    };
    let version_end = line[version_start..]
        .find(|character: char| !character.is_ascii_digit())
        .map_or(line.len(), |end| version_start + end);
    if version_end > version_start {
        line.replace_range(version_start..version_end, "[FORMAT]");
    }
    line
}

fn is_volatile_cargo_status(line: &str) -> bool {
    let line = line.trim_start();
    line.starts_with("Locking ")
        && line.contains(" package")
        && line.contains(" compatible version")
}

pub fn extract_group_handle(output: &str) -> String {
    extract_group_handles(output)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("diagnostic did not contain a group handle:\n{output}"))
}

pub fn extract_group_handles(output: &str) -> Vec<String> {
    const COMMAND_PREFIX: &str = "run `";
    const HANDLE_LEN: usize = 4;

    let handles = output
        .split(COMMAND_PREFIX)
        .skip(1)
        .filter_map(|command| command.split_once('`').map(|(command, _)| command))
        .filter_map(|command| {
            command
                .split_once(" explain ")
                .and_then(|(_, arguments)| arguments.split_whitespace().next())
        })
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert!(
        handles.iter().all(|handle| handle.len() == HANDLE_LEN
            && handle.bytes().all(|byte| byte.is_ascii_digit()
                || matches!(byte, b'a'..=b'h' | b'j'..=b'k' | b'm'..=b'n' | b'p'..=b't' | b'v'..=b'z'))),
        "diagnostic contained malformed group handles: {handles:?}"
    );
    handles
}

/// Replaces both the path as supplied and its filesystem-canonical form.
///
/// On macOS, temporary directories are commonly reported as `/var/...` by
/// `tempfile` but canonicalized to `/private/var/...` by rustc. Replace the
/// longer form first so replacing `/var/...` cannot leave a `/private` prefix.
pub fn normalize_path(text: &str, path: &Path, replacement: &str) -> String {
    let displayed = path.to_string_lossy().into_owned();
    let canonical = path
        .canonicalize()
        .ok()
        .map(|path| path.to_string_lossy().into_owned());

    let mut forms = [canonical.as_deref(), Some(displayed.as_str())]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    forms.sort_unstable_by_key(|form| std::cmp::Reverse(form.len()));
    forms.dedup();

    forms.into_iter().fold(text.to_owned(), |text, form| {
        text.replace(form, replacement)
    })
}

#[cfg(test)]
mod tests {
    use super::normalize_path;

    #[test]
    fn path_normalization_handles_lexical_and_canonical_forms() {
        let temp = tempfile::tempdir().expect("temporary directory should be created");
        let fixture = temp.path().join("fixture");
        std::fs::create_dir_all(&fixture).expect("fixture directory should be created");
        let canonical = fixture
            .canonicalize()
            .expect("fixture directory should be canonicalized");

        assert_eq!(
            normalize_path(
                &format!("{} and {}", fixture.display(), canonical.display()),
                &fixture,
                "[FIXTURE]",
            ),
            "[FIXTURE] and [FIXTURE]"
        );
    }
}
