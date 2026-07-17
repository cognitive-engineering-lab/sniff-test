//! Cargo execution, message processing, build-plan tracking, and outcome replay.

use std::collections::HashSet;
use std::path::Path;
use std::process::{Command, ExitCode};

use crate::cache::{artifact_id_from_extern_path, read_unit_outcome};
use crate::config::EXAMPLE_MANIFEST;
use anyhow::{Context, Result, anyhow, bail};

use super::args::{self, FrontendAction, FrontendCli, InitCliArgs, SniffTestArgs};
use super::plugin::{SNIFF_TEST_ARGS_ENV, frontend_args, modify_cargo, validate_manifest};

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
    if parsed_args
        .cargo_args
        .iter()
        .any(|arg| arg == "--message-format" || arg.starts_with("--message-format="))
    {
        bail!("pass --message-format to sniff-test itself, before any `--` separator");
    }
    let metadata = metadata_command(&parsed_args)
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
    cargo.args(["--message-format", "json-render-diagnostics"]);
    if std::env::var_os("CARGO_VERBOSE").is_some() {
        cargo.arg("-vv");
    }
    cargo.env(
        SNIFF_TEST_ARGS_ENV,
        serde_json::to_string(&args).context("failed to encode driver arguments")?,
    );
    modify_cargo(&mut cargo, &args)?;
    cargo.stdout(std::process::Stdio::piped());

    let mut child = cargo.spawn().context("failed to run Cargo")?;
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        return Err(anyhow!("failed to capture Cargo output"));
    };
    let mut plan = Vec::new();
    let mut planned = HashSet::new();
    let mut streamed = HashSet::new();
    for line in std::io::BufRead::lines(std::io::BufReader::new(stdout)) {
        let Ok(line) = line else {
            break;
        };
        process_cargo_message(&line, &args, &mut plan, &mut planned, &mut streamed);
    }
    let status = child.wait();
    let denied = consume_unit_outcomes(&args, &plan, &streamed);
    let status = status.context("failed to wait for Cargo")?;
    Ok(if status.success() {
        if denied {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        }
    } else if denied {
        ExitCode::FAILURE
    } else {
        match status.code() {
            Some(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
            None => ExitCode::FAILURE,
        }
    })
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

fn process_cargo_message(
    line: &str,
    args: &SniffTestArgs,
    plan: &mut Vec<String>,
    planned: &mut HashSet<String>,
    streamed: &mut HashSet<String>,
) {
    let Ok(message) = serde_json::from_str::<serde_json::Value>(line) else {
        return;
    };
    match message.get("reason").and_then(serde_json::Value::as_str) {
        Some("compiler-artifact") => {
            if let Some(id) = compiler_artifact_id(&message)
                && planned.insert(id.clone())
            {
                plan.push(id);
            }
        }
        Some("sniff-test-outcome") => {
            if let Some(id) = message
                .get("artifact-id")
                .and_then(serde_json::Value::as_str)
                && planned.insert(id.to_owned())
            {
                plan.push(id.to_owned());
            }
        }
        Some("sniff-test-artifact") => {
            if args.message_format == args::MessageFormat::Json {
                println!("{line}");
            }
            if let Some(id) = message
                .get("artifact")
                .and_then(|artifact| artifact.get("artifact-id"))
                .and_then(serde_json::Value::as_str)
            {
                streamed.insert(id.to_owned());
            }
        }
        _ => {}
    }
}

fn compiler_artifact_id(message: &serde_json::Value) -> Option<String> {
    let filenames = message.get("filenames")?.as_array()?;
    let mut fallback = None;
    for name in filenames.iter().filter_map(serde_json::Value::as_str) {
        let path = Path::new(name);
        let Some(id) = artifact_id_from_extern_path(path) else {
            continue;
        };
        if path
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|dir| dir == "deps")
        {
            return Some(id);
        }
        fallback.get_or_insert(id);
    }
    fallback
}

fn consume_unit_outcomes(
    args: &SniffTestArgs,
    plan: &[String],
    streamed: &HashSet<String>,
) -> bool {
    let mut denied = false;
    for artifact_id in plan {
        match read_unit_outcome(&args.cache_dir(), artifact_id, env!("CARGO_PKG_VERSION")) {
            Ok(outcome) => {
                denied |= outcome.has_denied_findings;
                if args.message_format == args::MessageFormat::Json
                    && !streamed.contains(artifact_id)
                    && let Some(report_json) = &outcome.report_json
                {
                    println!("{report_json}");
                }
            }
            Err(error) if error.is_missing_file() => {}
            Err(error) => {
                eprintln!(
                    "sniff-test: warning: ignoring unit outcome for `{artifact_id}`: {error}"
                );
            }
        }
    }
    denied
}

fn metadata_command(args: &SniffTestArgs) -> cargo_metadata::MetadataCommand {
    let mut command = cargo_metadata::MetadataCommand::new();
    command.no_deps();
    command.other_options(metadata_cargo_args(&args.cargo_args));
    command
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
