use std::ffi::OsStr;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use crate::artifact_cache::default_cache_dir;
use crate::config::SniffTestConfig;
use anyhow::{Context, Result, bail};
use clap::Parser as _;
use rustc_driver::{Callbacks, Compilation};
use rustc_interface::interface;
use rustc_middle::ty::TyCtxt;
use rustc_span::symbol::Symbol;

use super::args::{ColorChoice, CrateOutputScope, DriverCli, MANIFEST_PATH_ENV, SniffTestArgs};
use super::driver::{analyze_crate, is_build_script, is_proc_macro, load_config};

pub(crate) const DRIVER_NAME: &str = "sniff-test-driver";
pub(crate) const SNIFF_TEST_ARGS_ENV: &str = "SNIFF_TEST_ARGS";
pub(crate) const SNIFF_TEST_RUN_ID_ENV: &str = "SNIFF_TEST_RUN_ID";

pub(super) fn render_error_chain(error: &anyhow::Error) -> String {
    let mut rendered = error.to_string();
    let causes = error.chain().skip(1).collect::<Vec<_>>();
    if causes.is_empty() {
        return rendered;
    }

    rendered.push_str("\n\nCaused by:");
    if let [cause] = causes.as_slice() {
        let _ = write!(rendered, "\n    {cause}");
    } else {
        for (index, cause) in causes.into_iter().enumerate() {
            let _ = write!(rendered, "\n    {index}: {cause}");
        }
    }
    rendered
}

pub(crate) fn validate_manifest(path: &Path) -> Result<()> {
    if !path.exists() {
        bail!("manifest path `{}` does not exist", path.display());
    }
    if path.is_dir() {
        bail!(
            "manifest path `{}` is a directory but expected a file",
            path.display()
        );
    }
    Ok(())
}

pub(crate) fn frontend_args(mut args: SniffTestArgs, target_dir: &Path) -> Result<SniffTestArgs> {
    if args.cache_dir.is_none() {
        args.cache_dir = Some(default_cache_dir(target_dir));
    }
    args.cache_dir = Some(
        std::path::absolute(args.cache_dir()).context("failed to make cache directory absolute")?,
    );
    args.manifest_path = Some(
        std::path::absolute(args.manifest_path())
            .context("failed to make manifest path absolute")?,
    );
    Ok(args)
}

pub(crate) fn modify_cargo(cargo: &mut Command, args: &SniffTestArgs) -> Result<()> {
    let driver = driver_path()?;

    if args.release {
        cargo.arg("--release");
    }

    if args.build_std {
        cargo.args(["-Z", "build-std=core,alloc,std"]);
    }

    let config = load_config(args).context("failed to load configuration")?;
    let rustflags = analysis_rustflags(args, &config);

    // Cargo's rustflags sources are mutually exclusive, checked in order:
    // CARGO_ENCODED_RUSTFLAGS, RUSTFLAGS, target.*.rustflags, build.rustflags.
    // Owning the highest-precedence channel and folding the user's flags into
    // it is the only way the analysis flags are guaranteed to apply; injecting
    // a lower-precedence source is silently ignored whenever the user has
    // RUSTFLAGS exported. Cargo fingerprints the flag content regardless of
    // source, so the sniff_test_* cfg cache-busting keeps working.
    cargo.env(
        "CARGO_ENCODED_RUSTFLAGS",
        encode_rustflags(user_rustflags(), &rustflags),
    );

    if let Some(manifest_path) = &args.manifest_path {
        cargo.env(MANIFEST_PATH_ENV, manifest_path);
    }

    if args.color != ColorChoice::Auto
        && !args
            .cargo_args
            .iter()
            .any(|arg| arg == "--color" || arg.starts_with("--color="))
    {
        cargo.args(["--color", args.color.as_cargo_arg()]);
    }

    cargo.args(&args.cargo_args);

    // Like Clippy's lintcheck recursive mode, use RUSTC_WRAPPER rather than
    // RUSTC_WORKSPACE_WRAPPER so dependency artifacts are analyzed and cached.
    cargo.env("RUSTC_WRAPPER", driver);
    cargo.env_remove("RUSTC_WORKSPACE_WRAPPER");
    Ok(())
}

#[must_use]
pub fn driver_main() -> ExitCode {
    match try_driver_main() {
        Ok(exit_code) => exit_code,
        Err(error) => {
            eprintln!("error: {}", render_error_chain(&error));
            ExitCode::FAILURE
        }
    }
}

fn try_driver_main() -> Result<ExitCode> {
    let original_args = std::env::args().collect::<Vec<_>>();
    let is_info_query = |args: &[String]| {
        args.iter().any(|arg| {
            matches!(arg.as_str(), "--version" | "-V" | "-vV" | "-Vv" | "--print")
                || arg.starts_with("--print=")
        })
    };
    let is_rustc_wrapper_invocation = original_args
        .get(1)
        .map(Path::new)
        .and_then(Path::file_stem)
        == Some(OsStr::new("rustc"));
    if is_rustc_wrapper_invocation {
        let mut compiler_args = original_args;
        compiler_args.remove(1);
        if is_info_query(&compiler_args) {
            rustc_driver::run_compiler(&compiler_args, &mut DefaultCallbacks);
            return Ok(ExitCode::SUCCESS);
        }

        let source = std::env::var(SNIFF_TEST_ARGS_ENV)
            .with_context(|| format!("missing {SNIFF_TEST_ARGS_ENV}"))?;
        let mut args: SniffTestArgs = serde_json::from_str(&source)
            .with_context(|| format!("failed to decode {SNIFF_TEST_ARGS_ENV}"))?;
        args.under_cargo = true;
        return run_driver(&compiler_args, args);
    }

    let binary = original_args[0].clone();
    let driver = match DriverCli::try_parse_from(original_args) {
        Ok(driver) => driver,
        Err(error) => {
            let exit_code = error.exit_code();
            let _ = error.print();
            return Ok(ExitCode::from(u8::try_from(exit_code).unwrap_or(2)));
        }
    };
    let (compiler_args, args) = driver.into_parts(binary);
    let args = direct_args(args)?;
    if is_info_query(&compiler_args) {
        rustc_driver::run_compiler(&compiler_args, &mut DefaultCallbacks);
        return Ok(ExitCode::SUCCESS);
    }

    run_driver(&compiler_args, args)
}

fn direct_args(mut args: SniffTestArgs) -> Result<SniffTestArgs> {
    if args.manifest_path.is_none() {
        args.manifest_path = std::env::var_os(MANIFEST_PATH_ENV).map(std::path::PathBuf::from);
    }
    if let Some(path) = &args.manifest_path {
        validate_manifest(path)?;
    }
    args.manifest_path = Some(
        std::path::absolute(args.manifest_path())
            .context("failed to make manifest path absolute")?,
    );
    args.cache_dir = Some(
        std::path::absolute(args.cache_dir()).context("failed to make cache directory absolute")?,
    );
    Ok(args)
}

fn run_driver(compiler_args: &[String], args: SniffTestArgs) -> Result<ExitCode> {
    let mut compiler_args = compiler_args.to_owned();
    // The safety analysis reads THIR in `after_analysis`, after MIR building
    // would normally have stolen it. Appending here covers cargo mode, direct
    // mode, and user-RUSTFLAGS scenarios alike; the flag is UNTRACKED, so it
    // never perturbs cargo fingerprints. Cost: THIR stays allocated for the
    // whole compilation of each unit.
    let has_no_steal_thir = compiler_args.iter().any(|arg| arg == "-Zno-steal-thir")
        || compiler_args
            .windows(2)
            .any(|pair| pair[0] == "-Z" && pair[1] == "no-steal-thir");
    if !has_no_steal_thir {
        compiler_args.push(String::from("-Zno-steal-thir"));
    }
    let config = load_config(&args).context("failed to load configuration")?;
    let output_scope =
        CrateOutputScope::current(&args).context("failed to determine crate output scope")?;
    let mut callbacks = SniffTestCallbacks {
        args,
        config,
        output_scope,
    };
    // Fatal compile errors unwind with `FatalErrorMarker`; catching them here
    // turns that into rustc's ordinary exit status, matching the direct-mode
    // help text.
    Ok(rustc_driver::catch_with_exit_code(|| {
        rustc_driver::run_compiler(&compiler_args, &mut callbacks);
    }))
}

pub(crate) fn driver_path() -> Result<std::path::PathBuf> {
    let mut path = std::env::current_exe()
        .context("failed to locate current executable")?
        .with_file_name(DRIVER_NAME);
    if cfg!(windows) {
        path.set_extension("exe");
    }
    Ok(path)
}

pub(crate) fn rustc_version() -> String {
    let version = rustc_interface::util::rustc_version_str()
        .expect("linked rustc does not provide an embedded version");
    format!("rustc {version}")
}

fn stable_hash(source: &[u8]) -> u64 {
    // 64-bit FNV-1a: stable, small, and enough for Cargo cache fingerprinting.
    const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    source.iter().fold(FNV_OFFSET_BASIS, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(FNV_PRIME)
    })
}

fn analysis_rustflags(args: &SniffTestArgs, config: &SniffTestConfig) -> Vec<String> {
    let cache_location_hash = stable_hash(args.cache_dir().as_os_str().as_encoded_bytes());
    let overflow_checks = args
        .overflow_checks
        .unwrap_or(config.compiler.overflow_checks);
    let mut rustflags = vec![
        "--cfg".to_owned(),
        format!("sniff_test_cache_{cache_location_hash:016x}"),
        "--cfg".to_owned(),
        format!("sniff_test_tool_{}", env!("SNIFF_TEST_SOURCE_STAMP")),
        // Workspace consumers need upstream MIR to materialize exact
        // monomorphization overlays (for example, trait dispatch selected by
        // a workspace-local type).
        "-Z".to_owned(),
        "always-encode-mir".to_owned(),
    ];
    if args.release {
        // The checker reads optimized MIR. Release mode disables debug
        // assertions, and this pins rustc's optimized MIR default.
        rustflags.extend(["-Z", "mir-opt-level=2"].map(String::from));
    }
    for flag in config.compiler.inline_mir.rustc_flags() {
        // Keep this after `mir-opt-level` so explicit inlining policy wins.
        rustflags.extend(["-Z".to_owned(), (*flag).to_owned()]);
    }
    if let Some(flag) = overflow_checks.rustc_flag() {
        rustflags.extend(["-C".to_owned(), flag.to_owned()]);
    }
    rustflags
}

fn tracked_config_files_from_config(
    args: &SniffTestArgs,
    config: &SniffTestConfig,
) -> Vec<PathBuf> {
    let manifest_path = args.manifest_path();
    if !manifest_path.exists() {
        return Vec::new();
    }
    let mut files = vec![manifest_path];
    files.extend(config.contracts.resolved_override_files().iter().cloned());
    files
}

fn encode_rustflags(user_flags: Vec<String>, tool_flags: &[String]) -> String {
    user_flags
        .into_iter()
        .chain(tool_flags.iter().cloned())
        .collect::<Vec<_>>()
        .join("\u{1f}")
}

/// The rustflags the user's build would otherwise see: the env vars cargo
/// consults first, else `build.rustflags` from config files (best effort via
/// `cargo config get`). Config-file `target.*.rustflags` entries are not
/// recovered and stay masked for the analysis build.
fn user_rustflags() -> Vec<String> {
    if let Ok(encoded) = std::env::var("CARGO_ENCODED_RUSTFLAGS") {
        if encoded.is_empty() {
            return Vec::new();
        }
        return encoded.split('\u{1f}').map(str::to_owned).collect();
    }
    if let Ok(plain) = std::env::var("RUSTFLAGS") {
        return plain.split_whitespace().map(str::to_owned).collect();
    }
    config_build_rustflags().unwrap_or_default()
}

fn config_build_rustflags() -> Option<Vec<String>> {
    let output = Command::new("cargo")
        .args([
            "config",
            "get",
            "--format",
            "json-value",
            "build.rustflags",
            "-Zunstable-options",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        // Routinely fails when the key is unset; nothing to fold in.
        return None;
    }
    match serde_json::from_slice::<serde_json::Value>(&output.stdout).ok()? {
        serde_json::Value::Array(values) => Some(
            values
                .into_iter()
                .filter_map(|value| value.as_str().map(str::to_owned))
                .collect(),
        ),
        serde_json::Value::String(flags) => {
            Some(flags.split_whitespace().map(str::to_owned).collect())
        }
        _ => None,
    }
}

struct DefaultCallbacks;

impl Callbacks for DefaultCallbacks {}

struct SniffTestCallbacks {
    args: SniffTestArgs,
    config: SniffTestConfig,
    output_scope: CrateOutputScope,
}

impl Callbacks for SniffTestCallbacks {
    fn config(&mut self, config: &mut interface::Config) {
        // Direct driver invocations do not pass through `modify_cargo`, but
        // their artifacts must still expose MIR to downstream consumers.
        config.opts.unstable_opts.always_encode_mir = true;
        let is_build_script = config.opts.crate_name.as_deref() == Some("build_script_build");
        let is_proc_macro = config
            .opts
            .crate_types
            .contains(&rustc_session::config::CrateType::ProcMacro);
        if !should_track_workspace_run(self.output_scope, is_build_script, is_proc_macro) {
            return;
        }
        let encoded_args = std::env::var(SNIFF_TEST_ARGS_ENV).ok();
        let run_id = std::env::var(SNIFF_TEST_RUN_ID_ENV).ok();
        let config_files = tracked_config_files_from_config(&self.args, &self.config)
            .into_iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>();
        // These inputs are read outside rustc's normal source loading, so register
        // them explicitly in dep-info. Cargo will then rerun the driver when the
        // encoded arguments or any configuration file changes, as it does for Clippy.
        config.track_state = Some(Box::new(move |sess| {
            sess.env_depinfo.borrow_mut().insert((
                Symbol::intern(SNIFF_TEST_ARGS_ENV),
                encoded_args.as_deref().map(Symbol::intern),
            ));
            sess.env_depinfo.borrow_mut().insert((
                Symbol::intern(SNIFF_TEST_RUN_ID_ENV),
                run_id.as_deref().map(Symbol::intern),
            ));
            for path in &config_files {
                sess.file_depinfo.borrow_mut().insert(Symbol::intern(path));
            }
        }));
    }

    fn after_analysis(&mut self, _compiler: &interface::Compiler, tcx: TyCtxt<'_>) -> Compilation {
        if is_build_script(tcx) || is_proc_macro(tcx) {
            return Compilation::Continue;
        }

        analyze_crate(tcx, &self.args, &self.config, self.output_scope);
        Compilation::Continue
    }
}

const fn should_track_workspace_run(
    output_scope: CrateOutputScope,
    is_build_script: bool,
    is_proc_macro: bool,
) -> bool {
    matches!(output_scope, CrateOutputScope::Workspace) && !is_build_script && !is_proc_macro
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use anyhow::Context as _;

    use crate::config::SniffTestConfig;

    use super::{
        analysis_rustflags, encode_rustflags, render_error_chain, should_track_workspace_run,
        tracked_config_files_from_config,
    };
    use crate::cli::args::{CrateOutputScope, SniffTestArgs};

    #[test]
    fn error_chains_render_context_and_numbered_causes() {
        let error = Err::<(), _>(anyhow::anyhow!("low-level failure"))
            .context("middle context")
            .context("outer context")
            .expect_err("the test error should retain its context chain");

        assert_eq!(
            render_error_chain(&error),
            "outer context\n\nCaused by:\n    0: middle context\n    1: low-level failure"
        );
    }

    #[test]
    fn tool_rustflags_append_to_user_flags_in_encoded_form() {
        assert_eq!(
            encode_rustflags(
                vec![String::from("--cfg"), String::from("user_flag")],
                &[String::from("--cfg"), String::from("sniff_test_tool_abc")],
            ),
            "--cfg\u{1f}user_flag\u{1f}--cfg\u{1f}sniff_test_tool_abc"
        );
        assert_eq!(
            encode_rustflags(Vec::new(), &[String::from("-Zno-steal-thir")]),
            "-Zno-steal-thir"
        );
    }

    #[test]
    fn run_nonce_tracks_only_report_producing_workspace_units() {
        assert!(should_track_workspace_run(
            CrateOutputScope::Workspace,
            false,
            false
        ));
        assert!(!should_track_workspace_run(
            CrateOutputScope::Dependency,
            false,
            false
        ));
        assert!(!should_track_workspace_run(
            CrateOutputScope::Workspace,
            true,
            false
        ));
        assert!(!should_track_workspace_run(
            CrateOutputScope::Workspace,
            false,
            true
        ));
    }

    #[test]
    fn dependency_rustflags_make_upstream_mir_available_to_consumers() {
        let flags = analysis_rustflags(&SniffTestArgs::default(), &SniffTestConfig::default());

        assert!(
            flags
                .windows(2)
                .any(|pair| pair == ["-Z", "always-encode-mir"])
        );
    }

    #[test]
    fn policy_changes_preserve_dependency_rustflags() {
        let dir = tempfile::tempdir().expect("tempdir should be created");
        let manifest = dir.path().join("sniff-test.toml");
        let override_file = dir.path().join("override.toml");
        std::fs::write(
            &manifest,
            r#"
                [contracts]
                override-files = ["override.toml"]
            "#,
        )
        .expect("manifest should be written");
        std::fs::write(
            &override_file,
            r##"
                [overrides]
                "crate::f" = "# Panics\n"
            "##,
        )
        .expect("override should be written");

        let args = SniffTestArgs {
            manifest_path: Some(PathBuf::from(&manifest)),
            ..SniffTestArgs::default()
        };
        let config = SniffTestConfig::from_manifest_path(&manifest).expect("config should load");

        assert_eq!(
            tracked_config_files_from_config(&args, &config),
            [manifest.clone(), override_file.clone()]
        );
        let before = analysis_rustflags(&args, &config);

        std::fs::write(
            &override_file,
            r##"
                [overrides]
                "crate::f" = "# Safety\n"
            "##,
        )
        .expect("override should be updated");
        let changed_policy =
            SniffTestConfig::from_manifest_path(&manifest).expect("changed config should load");

        assert_eq!(before, analysis_rustflags(&args, &changed_policy));
    }

    #[test]
    fn overflow_check_mode_adds_its_dependency_rustflag() {
        let args = SniffTestArgs {
            cache_dir: Some(PathBuf::from("/tmp/sniff-test-cache-a")),
            ..SniffTestArgs::default()
        };
        let overflow = SniffTestConfig::from_manifest_str(
            "[compiler]\noverflow-checks = \"on\"\ninline-mir = \"off\"\n",
        )
        .expect("overflow config");
        let flags = analysis_rustflags(&args, &overflow);

        assert!(
            flags
                .windows(2)
                .any(|pair| pair == ["-C", "overflow-checks=yes"])
        );
    }
}
