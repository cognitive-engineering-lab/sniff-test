#![allow(dead_code)]

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

static CARGO_SNIFF_TEST_PATH: LazyLock<OsString> = LazyLock::new(|| {
    let canon = Path::new("../target/debug/cargo-sniff-test").canonicalize();
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

    let cargo_dirs = subdirectories(root)
        .filter(|dir_path| is_cargo_project(dir_path))
        .map(|path| {
            snapshot_cargo_dir(&path)?;
            Ok(path)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    write_review_script(&cargo_dirs)?;

    Ok(())
}

fn subdirectories(root: PathBuf) -> impl Iterator<Item = PathBuf> {
    WalkDir::new(root)
        .min_depth(1)
        .into_iter()
        .flatten()
        .filter(|e| e.metadata().map(|m| m.is_dir()).unwrap_or(false))
        .map(walkdir::DirEntry::into_path)
}

fn is_cargo_project(path: &Path) -> bool {
    path.join("Cargo.toml").exists()
}

fn snapshot_cargo_dir(path: &Path) -> anyhow::Result<()> {
    println!("snapshotting {}", path.display());
    let name = path
        .file_name()
        .expect("directory should have name")
        .to_str()
        .unwrap_or("[unknown name]")
        .to_owned();

    let out_path = path.to_path_buf();
    let out = cargo_sniff(path)?;

    insta::with_settings!({
        snapshot_path => out_path,
        filters => vec![
            (r"process didn't exit successfully: `(.*?)`", "process didn't exit successfully: [BINARY PATH ELIDED]")
        ],
        prepend_module_to_snapshot => false,
        omit_expression => true,
    }, {
        insta::assert_toml_snapshot!(name, &out);
    });

    println!("out is {out:?}");
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
    // register the sniff_tool tool
    cmd.env(
        "RUSTFLAGS",
        "-Zcrate-attr=feature(register_tool) -Zcrate-attr=register_tool(sniff_tool)",
    );
    cmd.current_dir(path);

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
