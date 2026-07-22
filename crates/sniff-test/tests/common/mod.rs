//! Helpers shared by the cli and fixtures harnesses.

// Each harness uses a subset of these helpers.
#![allow(dead_code)]

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::{Mutex, MutexGuard};

static NESTED_CARGO_LOCK: Mutex<()> = Mutex::new(());

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
        "{}",
        command_failure(&rustc.display().to_string(), &output)
    );

    String::from_utf8(output.stdout).expect("rustc sysroot output should be utf-8")
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

pub fn copy_dir_all(source: &Path, destination: &Path) -> io::Result<()> {
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

pub fn command_failure(command: &str, output: &std::process::Output) -> String {
    format!(
        "command failed: {command}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
