use std::borrow::Cow;
use std::path::PathBuf;
use std::process::Command;

use rustc_driver::{Callbacks, Compilation};
use rustc_interface::interface;
use rustc_middle::ty::TyCtxt;
use rustc_plugin::{CrateFilter, RustcPlugin, RustcPluginArgs, Utf8Path};
use sniff_test::cache::default_cache_dir;

use crate::args::{ColorChoice, MANIFEST_PATH_ENV, SniffTestArgs};
use crate::{absolute_path, analyze_crate, load_config};

pub struct SniffTestPlugin;

impl RustcPlugin for SniffTestPlugin {
    type Args = SniffTestArgs;

    fn version(&self) -> Cow<'static, str> {
        env!("CARGO_PKG_VERSION").into()
    }

    fn driver_name(&self) -> Cow<'static, str> {
        "cargo-sniff-test".into()
    }

    fn args(&self, target_dir: &Utf8Path) -> RustcPluginArgs<Self::Args> {
        let mut args = SniffTestArgs::parse_from_env();
        if args.cache_dir.is_none() {
            args.cache_dir = Some(default_cache_dir(target_dir));
        }
        args.manifest_path = Some(absolute_path(args.manifest_path()));

        RustcPluginArgs {
            args,
            filter: CrateFilter::AllCrates,
        }
    }

    fn modify_cargo(&self, cargo: &mut Command, args: &Self::Args) {
        let driver = self.driver_path();

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
        // Cargo replays cached rustc stderr for fresh artifacts. Include
        // report-affecting inputs in the rustc fingerprint so output matches.
        let mut rustflags = vec![
            "--cfg".to_owned(),
            format!("sniff_test_color_{}", args.color.as_cargo_arg()),
            "--cfg".to_owned(),
            format!("sniff_test_config_{config_hash:016x}"),
        ];
        if args.release {
            // The checker reads optimized MIR. Release mode disables debug
            // assertions, and these flags pin rustc's optimized MIR defaults
            // while keeping MIR inlining out of call traces.
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

        // rustc_plugin starts Cargo with RUSTC_WORKSPACE_WRAPPER, which only
        // wraps workspace crates. Panic reachability needs dependency summaries
        // too, so use RUSTC_WRAPPER for every rustc invocation and clear the
        // workspace wrapper to avoid nested driver invocations.
        // https://doc.rust-lang.org/cargo/reference/config.html#buildrustc-wrapper
        cargo.env("RUSTC_WRAPPER", driver);
        cargo.env_remove("RUSTC_WORKSPACE_WRAPPER");
    }

    fn run(
        self,
        compiler_args: Vec<String>,
        plugin_args: Self::Args,
    ) -> rustc_interface::interface::Result<()> {
        let compiler_args_for_driver = compiler_args.clone();
        let mut callbacks = SniffTestCallbacks {
            args: plugin_args,
            compiler_args,
        };
        rustc_driver::run_compiler(&compiler_args_for_driver, &mut callbacks);
        Ok(())
    }
}

fn stable_hash(source: &[u8]) -> u64 {
    // 64-bit FNV-1a: stable, small, and enough for Cargo cache fingerprinting.
    const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    source.iter().fold(FNV_OFFSET_BASIS, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(FNV_PRIME)
    })
}

impl SniffTestPlugin {
    fn driver_path(&self) -> PathBuf {
        std::env::current_exe()
            .unwrap_or_else(|error| {
                eprintln!("sniff-test: failed to locate current executable: {error}");
                std::process::exit(2);
            })
            .with_file_name(self.driver_name().as_ref())
    }
}

struct SniffTestCallbacks {
    args: SniffTestArgs,
    compiler_args: Vec<String>,
}

impl Callbacks for SniffTestCallbacks {
    fn after_analysis(&mut self, _compiler: &interface::Compiler, tcx: TyCtxt<'_>) -> Compilation {
        analyze_crate(tcx, &self.args, &self.compiler_args);
        Compilation::Continue
    }
}
