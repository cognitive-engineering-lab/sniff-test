#![allow(dead_code)]
#![feature(rustc_private)]

use serde::Serialize;
use std::{
    ffi::OsString,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::LazyLock,
};
use walkdir::WalkDir;

const CARGO_SNIFF_NAME: &str = "cargo-sniff-test";
const SNIFF_DRIVER_NAME: &str = "sniff-test-driver";
const BUILD_DIR: &str = "../target/debug";

static CARGO_SNIFF_TEST_PATH: LazyLock<OsString> = LazyLock::new(|| {
    let canon = Path::new(&format!("{BUILD_DIR}/{CARGO_SNIFF_NAME}")).canonicalize();
    canon
        .expect("issue with cargo sniff-test path")
        .into_os_string()
});

static SNIFF_TEST_DRIVER_PATH: LazyLock<OsString> = LazyLock::new(|| {
    let canon = Path::new(&format!("{BUILD_DIR}/{SNIFF_DRIVER_NAME}")).canonicalize();
    canon
        .expect("issue with cargo sniff-test path")
        .into_os_string()
});

#[derive(Debug, Serialize)]
pub struct SniffTestOutput {
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl TryFrom<Output> for SniffTestOutput {
    type Error = std::string::FromUtf8Error;
    fn try_from(value: Output) -> Result<Self, Self::Error> {
        Ok(SniffTestOutput {
            exit_code: value.status.code(),
            stdout: String::from_utf8(value.stdout)?,
            stderr: String::from_utf8(value.stderr)?,
        })
    }
}

#[test]
fn snapshots() -> anyhow::Result<()> {
    let root = Path::new(".").canonicalize()?;

    println!("root is {root:?}");

    let mut cargo_dirs = Vec::new();
    let mut processed_dirs = std::collections::HashSet::new();

    for entry in WalkDir::new(&root).min_depth(1).into_iter().flatten() {
        let path = entry.path();

        if !entry.metadata().map(|m| m.is_dir()).unwrap_or(false) {
            continue;
        }

        // Skip if we've already processed this directory as part of a cargo project
        if processed_dirs.contains(path) {
            continue;
        }

        if is_cargo_project(path) {
            // Process as a cargo project
            snapshot_cargo_dir(path, &root)?;
            cargo_dirs.push(path.to_path_buf());

            // Mark this directory and all subdirectories as processed
            mark_descendants_as_processed(path, &mut processed_dirs);
        } else if has_rust_files(path) && !is_inside_cargo_project(path, &root) {
            // Process individual .rs files in this directory
            snapshot_rust_files_dir(path, &root)?;
            cargo_dirs.push(path.to_path_buf());
            processed_dirs.insert(path.to_path_buf());
        }
    }

    write_review_script(&cargo_dirs)?;

    Ok(())
}

fn mark_descendants_as_processed(path: &Path, processed: &mut std::collections::HashSet<PathBuf>) {
    for entry in WalkDir::new(path).into_iter().flatten() {
        if entry.metadata().map(|m| m.is_dir()).unwrap_or(false) {
            processed.insert(entry.path().to_path_buf());
        }
    }
}

fn is_inside_cargo_project(path: &Path, root: &Path) -> bool {
    let mut current = path;
    while let Some(parent) = current.parent() {
        if parent == root {
            return false;
        }
        if is_cargo_project(parent) {
            return true;
        }
        current = parent;
    }
    false
}

fn has_rust_files(path: &Path) -> bool {
    std::fs::read_dir(path)
        .ok()
        .and_then(|entries| {
            entries.flatten().find(|entry| {
                entry.path().extension().and_then(|s| s.to_str()) == Some("rs")
                    && entry.metadata().map(|m| m.is_file()).unwrap_or(false)
            })
        })
        .is_some()
}

fn is_cargo_project(path: &Path) -> bool {
    path.join("Cargo.toml").exists()
}

fn snapshot_cargo_dir(path: &Path, root: &Path) -> anyhow::Result<()> {
    let name = path
        .file_name()
        .expect("directory should have name")
        .to_str()
        .unwrap_or("[unknown name]")
        .to_owned();

    let out_path = path.to_path_buf();
    let out = cargo_sniff(path)?;

    // panic!(
    //     "root is {}",
    //     root.to_str().expect("should be valid unicode")
    // );
    insta::with_settings!({
        snapshot_path => out_path,
        filters => vec![
            (r"process didn't exit successfully: `(.*?)`", "process didn't exit successfully: [BINARY PATH ELIDED]"),
            (root.to_str().expect("should be valid unicode"), "[SNIFF_TEST_DIR]")
        ],
        prepend_module_to_snapshot => false,
        omit_expression => true,
    }, {
        insta::assert_toml_snapshot!(name, &out);
    });

    println!("out is {out:?}");
    Ok(())
}

fn snapshot_rust_files_dir(path: &Path, root: &Path) -> anyhow::Result<()> {
    println!("snapshotting rust files in {}", path.display());

    let rust_files: Vec<_> = std::fs::read_dir(path)?
        .flatten()
        .filter(|entry| {
            entry.path().extension().and_then(|s| s.to_str()) == Some("rs")
                && entry.metadata().map(|m| m.is_file()).unwrap_or(false)
        })
        .collect();

    for entry in rust_files {
        let file_path = entry.path();
        snapshot_single_rust_file(&file_path, root)?;
    }

    Ok(())
}

fn snapshot_single_rust_file(file_path: &Path, root: &Path) -> anyhow::Result<()> {
    println!("  snapshotting rust file {}", file_path.display());

    let name = file_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("[unknown]")
        .to_owned();

    let out_path = file_path.parent().unwrap_or(Path::new(".")).to_path_buf();
    let out = rustc_sniff(file_path)?;

    insta::with_settings!({
        snapshot_path => out_path,
        filters => vec![
            (r"process didn't exit successfully: `(.*?)`", "process didn't exit successfully: [BINARY PATH ELIDED]"),
            (root.to_str().expect("should be valid unicode"), "[SNIFF_TEST_DIR]")
        ],
        prepend_module_to_snapshot => false,
        omit_expression => true,
    }, {
        insta::assert_toml_snapshot!(name, &out);
    });

    println!("  file output is {out:?}");
    Ok(())
}

fn cargo_sniff(path: &Path) -> anyhow::Result<SniffTestOutput> {
    // cargo clean first
    Command::new("cargo")
        .arg("clean")
        .current_dir(path)
        .output()?;

    println!("path is {:?}", CARGO_SNIFF_TEST_PATH.clone().into_string());
    let mut cmd = Command::new(&*CARGO_SNIFF_TEST_PATH);
    cmd.env("CARGO_TERM_COLOR", "never");
    cmd.current_dir(path);

    Ok(cmd.output()?.try_into()?)
}

fn rustc_sniff(file_path: &Path) -> anyhow::Result<SniffTestOutput> {
    let mut cmd = Command::new(&*SNIFF_TEST_DRIVER_PATH);

    // Env vars needed for the single invocation of the driver to work.
    cmd.env("RUSTC_PLUGIN_ALL_TARGETS", "");
    cmd.env("RUSTC_WORKSPACE_WRAPPER", "");
    cmd.env("CARGO_TERM_COLOR", "never");

    // We have to serialize the default plugin args so it knows what to do.
    cmd.env(
        "PLUGIN_ARGS",
        serde_json::to_string(&sniff_test::SniffTestArgs::default())
            .expect("default args should be serializeable"),
    );

    // Link w/ our external attrs crate.
    cmd.arg("--extern").arg(format!(
        "sniff_test_attrs={BUILD_DIR}/libsniff_test_attrs.dylib"
    ));

    // Register the sniff_tool.
    cmd.arg("-Zcrate-attr=feature(register_tool)")
        .arg("-Zcrate-attr=register_tool(sniff_tool)")
        .arg("-Zcrate-attr=feature(custom_inner_attributes)");

    // TODO: should do this all the time i think
    cmd.arg("-Zno-codegen");

    // Pass in compilation argument.
    cmd.arg(file_path);

    Ok(cmd.output()?.try_into()?)
}

const REVIEW_SCRIPT_PATH: &str = "../review.sh";

fn write_review_script(cargo_dirs: &[PathBuf]) -> anyhow::Result<()> {
    let review_commands = cargo_dirs
        .iter()
        .map(|dir| format!("cargo insta review --workspace-root {};\n", dir.display()));

    let out = std::iter::once("#!/bin/bash\n".to_string())
        .chain(review_commands)
        .collect::<String>();

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(REVIEW_SCRIPT_PATH)?;

    file.write_all(out.as_bytes())?;

    // make executable if we can on unix
    #[cfg(unix)]
    {
        let mut perms = file.metadata()?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(REVIEW_SCRIPT_PATH, perms)?;
    }

    Ok(())
}
