//! Cargo execution, message processing, build-plan tracking, and outcome replay.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use crate::cache::{artifact_id_from_extern_path, read_unit_outcome};

use super::args::{self, SniffTestArgs};
use super::plugin::{
    RUSTC_VERSION_ENV, SNIFF_TEST_ARGS_ENV, current_rustc_version, frontend_args, modify_cargo,
    rustc_version_dir_component,
};

#[must_use]
pub fn cargo_frontend() -> ExitCode {
    if std::env::args()
        .skip(1)
        .take_while(|arg| arg != "--")
        .any(|arg| arg == "-V" || arg == "--version")
    {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }

    let parsed_args = SniffTestArgs::parse_from_env();
    if parsed_args
        .cargo_args
        .iter()
        .any(|arg| arg == "--message-format" || arg.starts_with("--message-format="))
    {
        eprintln!(
            "sniff-test: pass --message-format to sniff-test itself, before any `--` separator"
        );
        return ExitCode::FAILURE;
    }
    let metadata = match metadata_command(&parsed_args).exec() {
        Ok(metadata) => metadata,
        Err(error) => {
            eprintln!("sniff-test: failed to read Cargo metadata: {error}");
            return ExitCode::FAILURE;
        }
    };
    let parsed_args = discover_manifest(parsed_args, metadata.workspace_root.as_std_path());
    let rustc_version = current_rustc_version();
    let target_dir = metadata.target_directory.join(format!(
        "sniff-test-{}",
        rustc_version_dir_component(&rustc_version)
    ));
    let mut args = frontend_args(parsed_args, target_dir.as_std_path());
    args.workspace_manifests = metadata
        .packages
        .iter()
        .map(|package| absolute_path(package.manifest_path.clone().into_std_path_buf()))
        .collect();

    let mut cargo = Command::new("cargo");
    cargo.args(["check", "--target-dir"]).arg(&target_dir);
    cargo.args(["--message-format", "json-render-diagnostics"]);
    if std::env::var_os("CARGO_VERBOSE").is_some() {
        cargo.arg("-vv");
    }
    cargo.env(RUSTC_VERSION_ENV, &rustc_version);
    cargo.env(
        SNIFF_TEST_ARGS_ENV,
        serde_json::to_string(&args).unwrap_or_else(|error| {
            eprintln!("sniff-test: failed to encode driver arguments: {error}");
            std::process::exit(2);
        }),
    );
    modify_cargo(&mut cargo, &args);
    cargo.stdout(std::process::Stdio::piped());

    let mut child = match cargo.spawn() {
        Ok(child) => child,
        Err(error) => {
            eprintln!("sniff-test: failed to run Cargo: {error}");
            return ExitCode::FAILURE;
        }
    };
    let Some(stdout) = child.stdout.take() else {
        eprintln!("sniff-test: failed to capture Cargo output");
        let _ = child.kill();
        return ExitCode::FAILURE;
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
    match status {
        Ok(status) if status.success() => {
            if denied {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
        Ok(status) => {
            if denied {
                ExitCode::FAILURE
            } else {
                match status.code() {
                    Some(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
                    None => ExitCode::FAILURE,
                }
            }
        }
        Err(error) => {
            eprintln!("sniff-test: failed to wait for Cargo: {error}");
            ExitCode::FAILURE
        }
    }
}

fn discover_manifest(mut args: SniffTestArgs, workspace_root: &Path) -> SniffTestArgs {
    if args.manifest_path.is_some() {
        return args;
    }

    let cwd = std::env::current_dir().unwrap_or_else(|error| {
        eprintln!("sniff-test: failed to read current directory: {error}");
        std::process::exit(2);
    });
    let mut dir = cwd.as_path();
    loop {
        let candidate = dir.join(crate::config::DEFAULT_MANIFEST_FILE);
        if candidate.is_file() {
            args.manifest_path = Some(candidate);
            return args;
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
    args
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

pub(crate) fn absolute_path(path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .unwrap_or_else(|error| {
                eprintln!("sniff-test: failed to read current directory: {error}");
                std::process::exit(2);
            })
            .join(path)
    }
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
