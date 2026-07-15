use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use crate::cache::default_cache_dir;
use crate::config::SniffTestConfig;
use rustc_driver::{Callbacks, Compilation};
use rustc_interface::interface;
use rustc_middle::ty::TyCtxt;
use rustc_span::symbol::Symbol;

use super::args::{ColorChoice, MANIFEST_PATH_ENV, SniffTestArgParseError, SniffTestArgs};
use super::cargo::absolute_path;
use super::driver::{analyze_crate, load_config};

pub(crate) const DRIVER_NAME: &str = "sniff-test-driver";
pub(crate) const RUSTC_VERSION_ENV: &str = "SNIFF_TEST_RUSTC_VERSION";
pub(crate) const SNIFF_TEST_ARGS_ENV: &str = "SNIFF_TEST_ARGS";

pub(crate) fn frontend_args(mut args: SniffTestArgs, target_dir: &Path) -> SniffTestArgs {
    if args.cache_dir.is_none() {
        args.cache_dir = Some(default_cache_dir(target_dir));
    }
    args.cache_dir = Some(absolute_path(args.cache_dir()));
    args.manifest_path = Some(absolute_path(args.manifest_path()));
    args
}

pub(crate) fn modify_cargo(cargo: &mut Command, args: &SniffTestArgs) {
    let driver = driver_path();

    if args.release {
        cargo.arg("--release");
    }

    if args.build_std {
        cargo.args(["-Z", "build-std=core,alloc,std"]);
    }

    let config = load_config(args);
    let config_hash = config_hash(args, &config);
    let overflow_checks = args
        .overflow_checks
        .unwrap_or(config.analysis.overflow_checks);
    let inline_mir = config.analysis.inline_mir;
    // Cargo replays cached rustc stderr/stdout for fresh artifacts. Include
    // report-affecting inputs in the rustc fingerprint so output matches.
    let mut rustflags = vec![
        "--cfg".to_owned(),
        format!("sniff_test_color_{}", args.color.as_cargo_arg()),
        "--cfg".to_owned(),
        format!("sniff_test_config_{config_hash:016x}"),
        "--cfg".to_owned(),
        format!("sniff_test_tool_{}", env!("SNIFF_TEST_SOURCE_STAMP")),
    ];
    if args.release {
        // The checker reads optimized MIR. Release mode disables debug
        // assertions, and this pins rustc's optimized MIR default.
        rustflags.extend(["-Z", "mir-opt-level=2"].map(String::from));
    }
    for flag in inline_mir.rustc_flags() {
        // Keep this after `mir-opt-level` so explicit inlining policy wins.
        rustflags.extend(["-Z".to_owned(), (*flag).to_owned()]);
    }
    if let Some(flag) = overflow_checks.rustc_flag() {
        rustflags.extend(["-C".to_owned(), flag.to_owned()]);
    }

    // Cargo's rustflags sources are mutually exclusive, checked in order:
    // CARGO_ENCODED_RUSTFLAGS, RUSTFLAGS, target.*.rustflags, build.rustflags.
    // Owning the highest-precedence channel and folding the user's flags into
    // it is the only way the analysis flags are guaranteed to apply; injecting
    // a lower-precedence source is silently ignored whenever the user has
    // RUSTFLAGS exported. Cargo fingerprints the flag content regardless of
    // source, so the sniff_test_* cfg cache-busting keeps working.
    cargo.env(
        "CARGO_ENCODED_RUSTFLAGS",
        compose_encoded_rustflags(&rustflags),
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
}

pub fn driver_main() -> ExitCode {
    let original_args = std::env::args().collect::<Vec<_>>();
    let separator = original_args.iter().rposition(|arg| arg == "--");
    if separator.is_none() && second_arg_is_rustc(&original_args) {
        let mut compiler_args = original_args;
        strip_rustc_wrapper_arg(&mut compiler_args);
        if is_info_query(&compiler_args) {
            rustc_driver::run_compiler(&compiler_args, &mut DefaultCallbacks);
            return ExitCode::SUCCESS;
        }

        let mut args = match args_from_env() {
            Ok(args) => args,
            Err(error) => {
                eprintln!("{error}");
                return ExitCode::FAILURE;
            }
        };
        args.under_cargo = true;
        return run_driver(&compiler_args, args);
    }

    let Some(separator) = separator else {
        if is_help_request(&original_args) {
            print_driver_help();
            return ExitCode::SUCCESS;
        }

        if is_version_request(&original_args) {
            println!("{}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }

        eprintln!("sniff-test: direct driver mode requires `--` before sniff-test arguments");
        print_driver_help();
        return ExitCode::FAILURE;
    };

    let mut compiler_args = vec![original_args[0].clone()];
    compiler_args.extend(original_args[1..separator].iter().cloned());
    strip_rustc_wrapper_arg(&mut compiler_args);
    let args = match direct_args(original_args[(separator + 1)..].iter().cloned()) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("sniff-test: {error}");
            return ExitCode::from(2);
        }
    };
    if compiler_args.len() == 1 {
        eprintln!("sniff-test: direct driver mode requires rustc arguments before `--`");
        return ExitCode::FAILURE;
    }
    if is_info_query(&compiler_args) {
        rustc_driver::run_compiler(&compiler_args, &mut DefaultCallbacks);
        return ExitCode::SUCCESS;
    }

    run_driver(&compiler_args, args)
}

fn second_arg_is_rustc(args: &[String]) -> bool {
    args.get(1).map(Path::new).and_then(Path::file_stem) == Some(OsStr::new("rustc"))
}

fn strip_rustc_wrapper_arg(args: &mut Vec<String>) {
    if second_arg_is_rustc(args) {
        args.remove(1);
    }
}

fn args_from_env() -> Result<SniffTestArgs, String> {
    match std::env::var(SNIFF_TEST_ARGS_ENV) {
        Ok(source) => serde_json::from_str::<SniffTestArgs>(&source).map_err(|error| {
            format!("sniff-test: failed to decode {SNIFF_TEST_ARGS_ENV}: {error}")
        }),
        Err(error) => Err(format!(
            "sniff-test: missing {SNIFF_TEST_ARGS_ENV}: {error}"
        )),
    }
}

fn direct_args(
    args: impl IntoIterator<Item = String>,
) -> Result<SniffTestArgs, SniffTestArgParseError> {
    let mut args = SniffTestArgs::parse_from_driver_args(args)?;
    if args.manifest_path.is_none() {
        args.manifest_path = std::env::var_os(MANIFEST_PATH_ENV).map(std::path::PathBuf::from);
    }
    args.manifest_path = Some(absolute_path(args.manifest_path()));
    args.cache_dir = Some(absolute_path(args.cache_dir()));
    Ok(args)
}

fn run_driver(compiler_args: &[String], args: SniffTestArgs) -> ExitCode {
    let mut compiler_args = compiler_args.to_owned();
    // The safety analysis reads THIR in `after_analysis`, after MIR building
    // would normally have stolen it. Appending here covers cargo mode, direct
    // mode, and user-RUSTFLAGS scenarios alike; the flag is UNTRACKED, so it
    // never perturbs cargo fingerprints. Cost: THIR stays allocated for the
    // whole compilation of each unit.
    if !has_no_steal_thir(&compiler_args) {
        compiler_args.push(String::from("-Zno-steal-thir"));
    }
    let mut callbacks = SniffTestCallbacks {
        args,
        compiler_args: compiler_args.clone(),
    };
    // Fatal compile errors unwind with `FatalErrorMarker`; catching them here
    // turns that into rustc's ordinary exit status, matching the direct-mode
    // help text.
    rustc_driver::catch_with_exit_code(|| {
        rustc_driver::run_compiler(&compiler_args, &mut callbacks);
    })
}

fn has_no_steal_thir(compiler_args: &[String]) -> bool {
    compiler_args.iter().any(|arg| arg == "-Zno-steal-thir")
        || compiler_args
            .windows(2)
            .any(|pair| pair[0] == "-Z" && pair[1] == "no-steal-thir")
}

pub(crate) fn driver_path() -> std::path::PathBuf {
    let mut path = std::env::current_exe()
        .unwrap_or_else(|error| {
            eprintln!("sniff-test: failed to locate current executable: {error}");
            std::process::exit(2);
        })
        .with_file_name(DRIVER_NAME);
    if cfg!(windows) {
        path.set_extension("exe");
    }
    path
}

pub(crate) fn current_rustc_version() -> String {
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
    let output = Command::new(rustc).arg("-Vv").output();
    let Ok(output) = output else {
        return String::from("rustc unknown");
    };
    if !output.status.success() {
        return String::from("rustc unknown");
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .filter(|line| !line.is_empty())
        .unwrap_or("rustc unknown")
        .to_owned()
}

pub(crate) fn rustc_version() -> String {
    std::env::var(RUSTC_VERSION_ENV).unwrap_or_else(|_| current_rustc_version())
}

pub(crate) fn rustc_version_dir_component(version: &str) -> String {
    sanitize_component(version)
}

fn stable_hash(source: &[u8]) -> u64 {
    // 64-bit FNV-1a: stable, small, and enough for Cargo cache fingerprinting.
    const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    source.iter().fold(FNV_OFFSET_BASIS, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(FNV_PRIME)
    })
}

fn config_hash(args: &SniffTestArgs, config: &SniffTestConfig) -> u64 {
    let mut source = Vec::new();
    for path in tracked_config_files_from_config(args, config) {
        let Ok(contents) = std::fs::read(&path) else {
            continue;
        };
        source.extend_from_slice(path.as_os_str().as_encoded_bytes());
        source.push(0);
        source.extend_from_slice(&contents);
        source.push(0);
    }
    if source.is_empty() {
        0
    } else {
        stable_hash(&source)
    }
}

fn tracked_config_files(args: &SniffTestArgs) -> Vec<PathBuf> {
    let manifest_path = args.manifest_path();
    if !manifest_path.exists() {
        return Vec::new();
    }
    let config = load_config(args);
    tracked_config_files_from_config(args, &config)
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
    files.extend(
        config
            .documentation
            .resolved_override_files()
            .iter()
            .cloned(),
    );
    files
}

fn compose_encoded_rustflags(tool_flags: &[String]) -> String {
    encode_rustflags(user_rustflags(), tool_flags)
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

fn sanitize_component(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();

    if sanitized.is_empty() {
        String::from("unknown")
    } else {
        sanitized
    }
}

fn is_help_request(args: &[String]) -> bool {
    args.len() == 1 || args.iter().any(|arg| arg == "--help" || arg == "-h")
}

fn is_info_query(args: &[String]) -> bool {
    args.iter().any(|arg| {
        arg == "--version"
            || arg == "-V"
            || arg == "-vV"
            || arg == "-Vv"
            || arg == "--print"
            || arg.starts_with("--print=")
    })
}

fn is_version_request(args: &[String]) -> bool {
    args.iter().any(|arg| arg == "--version" || arg == "-V")
}

fn print_driver_help() {
    println!(
        "sniff-test-driver runs sniff-test with rustc-style arguments.\n\n\
Usage:\n    sniff-test-driver [RUSTC-ARGS] -- [SNIFF-TEST-ARGS]\n\n\
SNIFF-TEST-ARGS:\n    --manifest PATH\n    --cache-dir DIR\n    --color auto|always|never\n    --message-format human|json\n\n\
Cargo frontend options such as --release, --build-std, and --overflow-checks\n\
belong to `cargo sniff-test`; pass equivalent rustc flags before `--` in direct mode.\n\
Direct mode follows rustc exit status; use cargo sniff-test for fail-on-panic policy.\n\n\
This binary is normally invoked by `cargo sniff-test` as a RUSTC_WRAPPER."
    );
}

struct DefaultCallbacks;

impl Callbacks for DefaultCallbacks {}

struct SniffTestCallbacks {
    args: SniffTestArgs,
    compiler_args: Vec<String>,
}

impl Callbacks for SniffTestCallbacks {
    fn config(&mut self, config: &mut interface::Config) {
        let encoded_args = std::env::var(SNIFF_TEST_ARGS_ENV).ok();
        let config_files = tracked_config_files(&self.args)
            .into_iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>();

        // WC: would be good to have a comment here explaining why we need to track the config files in this depinfo object.
        config.track_state = Some(Box::new(move |sess| {
            sess.env_depinfo.borrow_mut().insert((
                Symbol::intern(SNIFF_TEST_ARGS_ENV),
                encoded_args.as_deref().map(Symbol::intern),
            ));
            for path in &config_files {
                sess.file_depinfo.borrow_mut().insert(Symbol::intern(path));
            }
        }));
    }

    fn after_analysis(&mut self, _compiler: &interface::Compiler, tcx: TyCtxt<'_>) -> Compilation {
        analyze_crate(tcx, &self.args, &self.compiler_args);
        Compilation::Continue
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::config::SniffTestConfig;

    use super::{config_hash, encode_rustflags, tracked_config_files_from_config};
    use crate::cli::SniffTestArgs;

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
    fn config_hash_includes_documentation_override_files() {
        let dir = tempfile::tempdir().expect("tempdir should be created");
        let manifest = dir.path().join("sniff-test.toml");
        let override_file = dir.path().join("override.toml");
        std::fs::write(
            &manifest,
            r#"
                [documentation]
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
        let before = config_hash(&args, &config);

        std::fs::write(
            &override_file,
            r##"
                [overrides]
                "crate::f" = "# Safety\n"
            "##,
        )
        .expect("override should be updated");

        assert_ne!(before, config_hash(&args, &config));
    }
}
