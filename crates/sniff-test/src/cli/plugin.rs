use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::process::{Command, ExitCode};

use crate::cache::default_cache_dir;
use rustc_driver::{Callbacks, Compilation};
use rustc_interface::interface;
use rustc_middle::ty::TyCtxt;
use rustc_span::symbol::Symbol;

use super::args::{ColorChoice, MANIFEST_PATH_ENV, SniffTestArgParseError, SniffTestArgs};
use super::{absolute_path, analyze_crate, load_config};

pub(crate) const DRIVER_NAME: &str = "sniff-test-driver";
pub(crate) const RUSTC_VERSION_ENV: &str = "SNIFF_TEST_RUSTC_VERSION";
pub(crate) const SNIFF_TEST_ARGS_ENV: &str = "SNIFF_TEST_ARGS";
pub(crate) const RAW_PANIC_STATUS_ENV: &str = "SNIFF_TEST_RAW_PANIC_STATUS";

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

    let config_hash = args
        .manifest_path
        .as_ref()
        .and_then(|path| std::fs::read(path).ok())
        .map_or(0, |source| stable_hash(&source));
    let config = load_config(args);
    let overflow_checks = args
        .overflow_checks
        .unwrap_or(config.analysis.overflow_checks);
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
        // assertions, and these flags pin rustc's optimized MIR defaults while
        // keeping MIR inlining out of call traces.
        rustflags.extend(["-Z", "inline-mir=no", "-Z", "mir-opt-level=2"].map(String::from));
    }
    if let Some(flag) = overflow_checks.rustc_flag() {
        rustflags.extend(["-C".to_owned(), flag.to_owned()]);
    }

    let rustflags = rustflags
        .iter()
        .map(|flag| format!("\"{flag}\""))
        .collect::<Vec<_>>()
        .join(",");
    let rustflags_cfg = format!("build.rustflags=[{rustflags}]");
    cargo.args(["--config", &rustflags_cfg]);

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

        let args = match args_from_env() {
            Ok(args) => args,
            Err(error) => {
                eprintln!("{error}");
                return ExitCode::FAILURE;
            }
        };
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
    let mut callbacks = SniffTestCallbacks {
        args,
        compiler_args: compiler_args.to_owned(),
    };
    rustc_driver::run_compiler(compiler_args, &mut callbacks);
    ExitCode::SUCCESS
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
belong to `cargo sniff-test`; pass equivalent rustc flags before `--` in direct mode.\n\n\
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
        let manifest_path = self
            .args
            .manifest_path
            .as_ref()
            .map(|path| path.display().to_string());
        config.track_state = Some(Box::new(move |sess| {
            sess.env_depinfo.borrow_mut().insert((
                Symbol::intern(SNIFF_TEST_ARGS_ENV),
                encoded_args.as_deref().map(Symbol::intern),
            ));
            if let Some(manifest_path) = &manifest_path {
                sess.file_depinfo
                    .borrow_mut()
                    .insert(Symbol::intern(manifest_path));
            }
        }));
    }

    fn after_analysis(&mut self, _compiler: &interface::Compiler, tcx: TyCtxt<'_>) -> Compilation {
        analyze_crate(tcx, &self.args, &self.compiler_args);
        Compilation::Continue
    }
}
