//! Cargo command orchestration.

use std::ffi::OsString;
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use crate::artifact_cache::default_cache_dir;
use crate::config::EXAMPLE_MANIFEST;
use anyhow::{Context, Result, bail};

use super::args::{
    self, ColorChoice, ExplainCliArgs, FrontendAction, FrontendCli, InitCliArgs, SniffTestArgs,
    SourcePackage,
};
use super::explanations::{DiagnosticGroupHandle, ExplanationStore};
use super::plugin::{
    SNIFF_TEST_ARGS_ENV, frontend_args, modify_cargo, render_error_chain, validate_manifest,
};

#[must_use]
pub fn cargo_frontend() -> ExitCode {
    match try_cargo_frontend() {
        Ok(exit_code) => exit_code,
        Err(error) => {
            eprintln!("error: {}", render_error_chain(&error));
            ExitCode::FAILURE
        }
    }
}

fn try_cargo_frontend() -> Result<ExitCode> {
    let invoked_as_cargo_subcommand = std::env::args_os()
        .nth(1)
        .is_some_and(|argument| argument == "sniff-test");
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
        FrontendAction::Explain(args) => return run_explain(&args),
    };
    let cwd = std::env::current_dir().context("failed to read current directory")?;
    configure_explain_command(&mut parsed_args, invoked_as_cargo_subcommand, &cwd)?;
    if parsed_args.manifest_path.is_none() {
        parsed_args.manifest_path =
            std::env::var_os(args::MANIFEST_PATH_ENV).map(std::path::PathBuf::from);
    }
    if let Some(path) = &parsed_args.manifest_path {
        validate_manifest(path)?;
    }
    let mut metadata_command = cargo_metadata::MetadataCommand::new();
    metadata_command.other_options(metadata_cargo_args(&parsed_args.cargo_args));
    let metadata = metadata_command
        .exec()
        .context("failed to read Cargo metadata")?;
    let parsed_args = discover_manifest(parsed_args, metadata.workspace_root.as_std_path())?;
    let target_dir = metadata.target_directory.join("sniff-test");
    let mut args = frontend_args(parsed_args, target_dir.as_std_path())?;
    args.cargo_target_dir = Some(target_dir.as_std_path().to_owned());
    args.workspace_manifests = metadata
        .packages
        .iter()
        .filter(|package| metadata.workspace_members.contains(&package.id))
        .map(|package| -> Result<_> {
            package.manifest_path.canonicalize().with_context(|| {
                format!(
                    "failed to canonicalize workspace manifest {}",
                    package.manifest_path
                )
            })
        })
        .collect::<Result<_>>()?;
    args.source_packages = metadata
        .packages
        .iter()
        .map(|package| SourcePackage {
            root: package
                .manifest_path
                .parent()
                .unwrap_or(&package.manifest_path)
                .as_std_path()
                .to_owned(),
            identity: source_package_identity(package),
        })
        .collect();
    let mut cargo = Command::new("cargo");
    cargo.args(["check", "--target-dir"]).arg(&target_dir);
    if std::env::var_os("CARGO_VERBOSE").is_some() {
        cargo.arg("-vv");
    }
    let staging = tempfile::Builder::new()
        .prefix("sniff-test-explain-")
        .tempdir()
        .context("failed to create temporary explanation staging directory")?;
    args.explanation_staging_dir = Some(staging.path().to_owned());
    modify_cargo(&mut cargo, &args)?;
    cargo.env(
        SNIFF_TEST_ARGS_ENV,
        serde_json::to_string(&args).context("failed to encode driver arguments")?,
    );
    let status = cargo.status().context("failed to run Cargo")?;
    ExplanationStore::new(args.cache_dir())
        .publish(staging.path())
        .context("failed to publish diagnostic explanations")?;
    let Some(code) = status.code() else {
        return Ok(ExitCode::FAILURE);
    };
    Ok(ExitCode::from(u8::try_from(code).unwrap_or(1)))
}

fn cargo_home(
    cargo_home: Option<OsString>,
    user_home: Option<OsString>,
    cwd: &Path,
) -> Option<PathBuf> {
    let path = cargo_home
        .map(PathBuf::from)
        .or_else(|| user_home.map(|root| PathBuf::from(root).join(".cargo")))?;
    Some(if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    })
}

fn source_package_identity(package: &cargo_metadata::Package) -> String {
    let location = package.source.as_ref().map_or_else(
        || String::from("path"),
        |source| portable_package_source(&source.repr),
    );
    format!("{}@{}:{location}", package.name, package.version)
}

fn portable_package_source(source: &str) -> String {
    if source.starts_with("git+") {
        return source.rsplit_once('#').map_or_else(
            || String::from("git"),
            |(_, revision)| format!("git:{revision}"),
        );
    }
    if source.starts_with("registry+") || source.starts_with("sparse+") {
        return String::from("registry");
    }
    source.to_owned()
}

fn run_explain(args: &ExplainCliArgs) -> Result<ExitCode> {
    let handle = args
        .handle
        .parse::<DiagnosticGroupHandle>()
        .context("invalid diagnostic group handle")?;
    let cache_dir = explain_cache_dir(args)?;
    let groups = ExplanationStore::new(cache_dir)
        .explain(&handle)
        .with_context(|| format!("failed to explain diagnostic group `{handle}`"))?;
    let color = match args.color {
        ColorChoice::Auto => rustc_errors::ColorChoice::Auto,
        ColorChoice::Always => rustc_errors::ColorChoice::Always,
        ColorChoice::Never => rustc_errors::ColorChoice::Never,
    };
    let mut output = rustc_errors::AutoStream::new(io::stdout().lock(), color);
    let show_group_headers = groups.len() > 1;
    for (group_index, group) in groups.iter().enumerate() {
        if group_index > 0 {
            writeln!(output)?;
        }
        if show_group_headers {
            let key = group.key();
            if key.subtype().is_empty() {
                writeln!(output, "{}", key.function())?;
            } else {
                writeln!(output, "{} ({})", key.function(), key.subtype())?;
            }
        }
        for (diagnostic_index, diagnostic) in group.diagnostics().iter().enumerate() {
            if diagnostic_index > 0 {
                writeln!(output)?;
            }
            output.write_all(diagnostic.explanation().as_bytes())?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn explain_cache_dir(args: &ExplainCliArgs) -> Result<std::path::PathBuf> {
    if let Some(cache_dir) = &args.cache_dir {
        return std::path::absolute(cache_dir)
            .context("failed to make the explanation cache directory absolute");
    }
    let mut command = cargo_metadata::MetadataCommand::new();
    command.no_deps();
    if let Some(manifest) = &args.manifest_path {
        command.manifest_path(manifest);
    }
    let metadata = command
        .exec()
        .context("failed to read Cargo metadata while locating diagnostic explanations")?;
    Ok(default_cache_dir(
        metadata.target_directory.join("sniff-test").as_std_path(),
    ))
}

fn use_concise_explain_command(
    invoked_as_cargo_subcommand: bool,
    frontend_is_on_path: bool,
    cargo_locator_overridden: bool,
    args: &SniffTestArgs,
) -> bool {
    invoked_as_cargo_subcommand
        && frontend_is_on_path
        && !cargo_locator_overridden
        && args.cache_dir.is_none()
        && !args.cargo_args.iter().any(|argument| {
            matches!(
                argument.as_str(),
                "--manifest-path" | "-m" | "--config" | "--target-dir"
            ) || argument.starts_with("--manifest-path=")
                || argument.starts_with("--config=")
                || argument.starts_with("--target-dir=")
        })
}

fn configure_explain_command(
    args: &mut SniffTestArgs,
    invoked_as_cargo_subcommand: bool,
    cwd: &Path,
) -> Result<()> {
    let frontend =
        std::env::current_exe().context("failed to locate the sniff-test frontend executable")?;
    let custom_locator = cargo_locator_environment_is_custom(
        std::env::var_os("CARGO_TARGET_DIR").is_some(),
        std::env::var_os("CARGO_HOME"),
        std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }),
        cwd,
    );
    if !use_concise_explain_command(
        invoked_as_cargo_subcommand,
        frontend_is_on_path(&frontend),
        custom_locator,
        args,
    ) {
        args.frontend_executable = Some(frontend);
    }
    Ok(())
}

fn frontend_is_on_path(frontend: &Path) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    frontend_is_on_search_path(frontend, &path)
}

fn frontend_is_on_search_path(frontend: &Path, path: &std::ffi::OsStr) -> bool {
    let Ok(frontend) = frontend.canonicalize() else {
        return false;
    };
    std::env::split_paths(path)
        .find_map(|directory| {
            let candidate =
                directory.join(format!("cargo-sniff-test{}", std::env::consts::EXE_SUFFIX));
            executable_path(&candidate)
        })
        .is_some_and(|candidate| candidate == frontend)
}

fn executable_path(path: &Path) -> Option<PathBuf> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o111 == 0 {
            return None;
        }
    }
    path.canonicalize().ok()
}

fn cargo_locator_environment_is_custom(
    cargo_target_dir_is_set: bool,
    cargo_home_env: Option<OsString>,
    user_home: Option<OsString>,
    cwd: &Path,
) -> bool {
    if cargo_target_dir_is_set {
        return true;
    }
    let Some(cargo_home_env) = cargo_home_env else {
        return false;
    };
    cargo_home(Some(cargo_home_env), user_home.clone(), cwd) != cargo_home(None, user_home, cwd)
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

fn discover_manifest(args: SniffTestArgs, workspace_root: &Path) -> Result<SniffTestArgs> {
    if args.manifest_path.is_some() {
        return Ok(args);
    }

    let cwd = std::env::current_dir().context("failed to read current directory")?;
    Ok(discover_manifest_from(args, workspace_root, &cwd))
}

fn discover_manifest_from(
    mut args: SniffTestArgs,
    workspace_root: &Path,
    cwd: &Path,
) -> SniffTestArgs {
    let mut dir = cwd;
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
        "sniff-test: no {} found between {} and {}; using built-in defaults (public report roots, panic findings denied, safety findings warned)",
        crate::config::DEFAULT_MANIFEST_FILE,
        cwd.display(),
        workspace_root.display(),
    );
    args
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
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    use super::{
        cargo_home, cargo_locator_environment_is_custom, discover_manifest_from,
        frontend_is_on_search_path, metadata_cargo_args, portable_package_source, run_explain,
        use_concise_explain_command,
    };
    use crate::cli::args::{ExplainCliArgs, SniffTestArgs};

    #[test]
    fn invalid_explain_handle_is_rejected_before_locating_the_cargo_workspace() {
        let temporary = tempfile::tempdir().expect("temporary directory without a workspace");
        let args = ExplainCliArgs {
            handle: String::from("invalid"),
            manifest_path: Some(temporary.path().join("Cargo.toml")),
            cache_dir: None,
            color: crate::cli::args::ColorChoice::Auto,
        };

        let error = run_explain(&args).expect_err("reject the malformed handle");
        assert_eq!(error.to_string(), "invalid diagnostic group handle");
    }

    #[test]
    fn concise_explain_command_requires_cargo_dispatch_and_a_discoverable_default_cache() {
        let default = SniffTestArgs::default();
        assert!(use_concise_explain_command(true, true, false, &default));
        assert!(!use_concise_explain_command(false, true, false, &default));
        assert!(!use_concise_explain_command(true, false, false, &default));
        assert!(!use_concise_explain_command(true, true, true, &default));

        let mut custom_cache = default.clone();
        custom_cache.cache_dir = Some(PathBuf::from("custom-cache"));
        assert!(!use_concise_explain_command(
            true,
            true,
            false,
            &custom_cache
        ));

        for cargo_args in [
            vec![
                String::from("--manifest-path"),
                String::from("app/Cargo.toml"),
            ],
            vec![String::from("--manifest-path=app/Cargo.toml")],
            vec![String::from("-m"), String::from("app/Cargo.toml")],
            vec![String::from("--config=build.target-dir='custom'")],
            vec![String::from("--target-dir=custom")],
        ] {
            let mut explicit_manifest = default.clone();
            explicit_manifest.cargo_args = cargo_args;
            assert!(!use_concise_explain_command(
                true,
                true,
                false,
                &explicit_manifest
            ));
        }
    }

    #[test]
    fn frontend_path_detection_requires_the_same_binary() {
        let temporary = tempfile::tempdir().expect("temporary PATH directory");
        let selected_directory = temporary.path().join("selected");
        let other_directory = temporary.path().join("other");
        std::fs::create_dir_all(&selected_directory).expect("selected PATH directory");
        std::fs::create_dir_all(&other_directory).expect("other PATH directory");
        let frontend =
            selected_directory.join(format!("cargo-sniff-test{}", std::env::consts::EXE_SUFFIX));
        let other_frontend =
            other_directory.join(format!("cargo-sniff-test{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&frontend, "frontend").expect("frontend placeholder");
        std::fs::write(&other_frontend, "other frontend").expect("other frontend placeholder");
        #[cfg(unix)]
        for path in [&frontend, &other_frontend] {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
                .expect("executable frontend placeholder");
        }

        assert!(frontend_is_on_search_path(
            &frontend,
            selected_directory.as_os_str()
        ));
        assert!(!frontend_is_on_search_path(
            &other_directory.join("missing"),
            selected_directory.as_os_str()
        ));
        assert!(!frontend_is_on_search_path(
            &frontend,
            &std::env::join_paths([&other_directory, &selected_directory])
                .expect("ordered search path")
        ));
    }

    #[test]
    fn cargo_locator_environment_ignores_cargos_default_home_but_not_overrides() {
        let cwd = Path::new("/workspace");
        let user_home = Some(OsString::from("/users/example"));
        assert!(!cargo_locator_environment_is_custom(
            false,
            Some(OsString::from("/users/example/.cargo")),
            user_home.clone(),
            cwd,
        ));
        assert!(cargo_locator_environment_is_custom(
            false,
            Some(OsString::from("/custom/cargo-home")),
            user_home.clone(),
            cwd,
        ));
        assert!(cargo_locator_environment_is_custom(
            true,
            Some(OsString::from("/users/example/.cargo")),
            user_home,
            cwd,
        ));
    }

    #[test]
    fn implicit_config_discovery_selects_the_nearest_manifest() {
        let temporary = tempfile::tempdir().expect("temporary workspace");
        let workspace = temporary.path();
        let nested = workspace.join("crate/src");
        std::fs::create_dir_all(&nested).expect("nested working directory");
        std::fs::write(workspace.join("sniff-test.toml"), "").expect("workspace config");
        let discovered = discover_manifest_from(SniffTestArgs::default(), workspace, &nested);
        assert_eq!(
            discovered.manifest_path,
            Some(workspace.join("sniff-test.toml"))
        );
    }

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

    #[test]
    fn git_package_identity_uses_the_resolved_revision_not_checkout_location() {
        let revision = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(
            portable_package_source(&format!("git+file:///first/copy/dependency#{revision}")),
            portable_package_source(&format!("git+file:///second/copy/dependency#{revision}")),
        );
        assert_ne!(
            portable_package_source(&format!("git+file:///first/copy/dependency#{revision}")),
            portable_package_source(
                "git+file:///first/copy/dependency#fedcba9876543210fedcba9876543210fedcba98"
            ),
        );
        assert_eq!(
            portable_package_source("registry+file:///first/local/index"),
            portable_package_source("registry+file:///second/local/index"),
            "a local registry checkout path is not semantic package identity"
        );
        assert_eq!(
            portable_package_source("sparse+https://index.crates.io/"),
            "registry"
        );
    }

    #[test]
    fn cargo_home_defaults_to_the_user_cargo_directory() {
        assert_eq!(
            cargo_home(
                None,
                Some(OsString::from("/users/example")),
                Path::new("/workspace"),
            ),
            Some(PathBuf::from("/users/example/.cargo"))
        );
        assert_eq!(
            cargo_home(
                Some(OsString::from("/custom/cargo")),
                Some(OsString::from("/users/example")),
                Path::new("/workspace"),
            ),
            Some(PathBuf::from("/custom/cargo"))
        );
        assert_eq!(
            cargo_home(
                Some(OsString::from("relative-cargo-home")),
                None,
                Path::new("/workspace"),
            ),
            Some(PathBuf::from("/workspace/relative-cargo-home"))
        );
    }
}
