//! Cargo command orchestration.

use std::path::Path;
use std::process::{Command, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::EXAMPLE_MANIFEST;
use anyhow::{Context, Result, bail};

use super::args::{self, FrontendAction, FrontendCli, InitCliArgs, SniffTestArgs};
use super::plugin::{
    SNIFF_TEST_ARGS_ENV, SNIFF_TEST_RUN_ID_ENV, frontend_args, modify_cargo, validate_manifest,
};

#[must_use]
pub fn cargo_frontend() -> ExitCode {
    match try_cargo_frontend() {
        Ok(exit_code) => exit_code,
        Err(error) => {
            eprintln!("error: {error:?}");
            ExitCode::FAILURE
        }
    }
}

fn try_cargo_frontend() -> Result<ExitCode> {
    let cli = match FrontendCli::try_parse_env() {
        Ok(cli) => cli,
        Err(error) => {
            let exit_code = error.exit_code();
            let _ = error.print();
            return Ok(ExitCode::from(u8::try_from(exit_code).unwrap_or(2)));
        }
    };
    let mut parsed_args = match cli.into_action() {
        FrontendAction::Run(args) => args,
        FrontendAction::Init(args) => return run_init(&args),
    };
    if parsed_args.manifest_path.is_none() {
        parsed_args.manifest_path =
            std::env::var_os(args::MANIFEST_PATH_ENV).map(std::path::PathBuf::from);
    }
    if let Some(path) = &parsed_args.manifest_path {
        validate_manifest(path)?;
    }
    let mut metadata_command = cargo_metadata::MetadataCommand::new();
    metadata_command.no_deps();
    metadata_command.other_options(metadata_cargo_args(&parsed_args.cargo_args));
    let metadata = metadata_command
        .exec()
        .context("failed to read Cargo metadata")?;
    let parsed_args = discover_manifest(parsed_args, metadata.workspace_root.as_std_path())?;
    let target_dir = metadata.target_directory.join("sniff-test");
    let mut args = frontend_args(parsed_args, target_dir.as_std_path())?;
    args.workspace_manifests = metadata
        .packages
        .iter()
        .map(|package| -> Result<_> {
            package.manifest_path.canonicalize().with_context(|| {
                format!(
                    "failed to canonicalize workspace manifest {}",
                    package.manifest_path
                )
            })
        })
        .collect::<Result<_>>()?;

    let mut cargo = Command::new("cargo");
    cargo.args(["check", "--target-dir"]).arg(&target_dir);
    if std::env::var_os("CARGO_VERBOSE").is_some() {
        cargo.arg("-vv");
    }
    cargo.env(
        SNIFF_TEST_ARGS_ENV,
        serde_json::to_string(&args).context("failed to encode driver arguments")?,
    );
    // The workspace callback records this value in rustc dep-info. Changing it
    // makes Cargo rerun report-producing workspace units so each invocation
    // validates and reinterprets cached IR; dependency units never record it.
    cargo.env(SNIFF_TEST_RUN_ID_ENV, workspace_run_id());
    modify_cargo(&mut cargo, &args)?;
    let status = cargo.status().context("failed to run Cargo")?;
    let Some(code) = status.code() else {
        return Ok(ExitCode::FAILURE);
    };
    Ok(ExitCode::from(u8::try_from(code).unwrap_or(1)))
}

fn workspace_run_id() -> String {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}-{}", std::process::id(), elapsed.as_nanos())
}

fn run_init(args: &InitCliArgs) -> Result<ExitCode> {
    if args.manifest.exists() && !args.force {
        bail!(
            "{} already exists; pass --force to overwrite it",
            args.manifest.display()
        );
    }

    std::fs::write(&args.manifest, EXAMPLE_MANIFEST)
        .with_context(|| format!("failed to write `{}`", args.manifest.display()))?;

    println!("sniff-test: wrote {}", args.manifest.display());
    Ok(ExitCode::SUCCESS)
}

fn discover_manifest(mut args: SniffTestArgs, workspace_root: &Path) -> Result<SniffTestArgs> {
    if args.manifest_path.is_some() {
        return Ok(args);
    }

    let cwd = std::env::current_dir().context("failed to read current directory")?;
    let mut dir = cwd.as_path();
    loop {
        let candidate = dir.join(crate::config::DEFAULT_MANIFEST_FILE);
        if candidate.is_file() {
            args.manifest_path = Some(candidate);
            return Ok(args);
        }
        if dir == workspace_root || !dir.starts_with(workspace_root) {
            break;
        }
        match dir.parent() {
            Some(parent) => dir = parent,
            None => break,
        }
    }

    eprintln!(
        "sniff-test: no {} found between {} and {}; running with the empty default policy",
        crate::config::DEFAULT_MANIFEST_FILE,
        cwd.display(),
        workspace_root.display(),
    );
    Ok(args)
}

pub(crate) fn metadata_cargo_args(cargo_args: &[String]) -> Vec<String> {
    let mut metadata_args = Vec::new();
    let mut iter = cargo_args.iter();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--manifest-path" | "-m" | "--features" | "-F" | "--filter-platform" | "--color"
            | "--config" | "-Z" => {
                metadata_args.push(arg.clone());
                if let Some(value) = iter.next() {
                    metadata_args.push(value.clone());
                }
            }
            "--all-features" | "--no-default-features" | "--locked" | "--offline" | "--frozen" => {
                metadata_args.push(arg.clone());
            }
            other
                if other.starts_with("--manifest-path=")
                    || other.starts_with("--features=")
                    || other.starts_with("--filter-platform=")
                    || other.starts_with("--color=")
                    || other.starts_with("--config=") =>
            {
                metadata_args.push(arg.clone());
            }
            _ => {}
        }
    }

    metadata_args
}

#[cfg(test)]
mod tests {
    use super::metadata_cargo_args;

    #[test]
    fn metadata_cargo_args_keep_metadata_compatible_options() {
        let args = [
            "--manifest-path",
            "crate/Cargo.toml",
            "-p",
            "selected",
            "--features",
            "dangerous",
            "--offline",
            "--target",
            "wasm32-unknown-unknown",
        ]
        .map(String::from);

        assert_eq!(
            metadata_cargo_args(&args),
            [
                "--manifest-path",
                "crate/Cargo.toml",
                "--features",
                "dangerous",
                "--offline",
            ]
            .map(String::from)
        );
    }
}
