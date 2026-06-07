use std::borrow::Cow;
use std::path::PathBuf;
use std::process::Command;

use rustc_driver::{Callbacks, Compilation};
use rustc_interface::interface;
use rustc_middle::ty::TyCtxt;
use rustc_plugin::{CrateFilter, RustcPlugin, RustcPluginArgs, Utf8Path};
use sniff_test::cache::default_cache_dir;

use crate::args::{ColorChoice, MANIFEST_PATH_ENV, SniffTestArgs};
use crate::{absolute_path, analyze_crate};

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

        // Cargo replays cached rustc stderr for fresh artifacts. Include
        // report-affecting inputs in the rustc fingerprint so output matches.
        let config_hash = args
            .manifest_path
            .as_ref()
            .and_then(|path| std::fs::read(path).ok())
            .map_or(0, |source| stable_hash(&source));
        let fingerprint_cfg = format!(
            "build.rustflags=[\"--cfg\", \"sniff_test_color_{}\", \"--cfg\", \"sniff_test_config_{config_hash:016x}\"]",
            args.color.as_cargo_arg(),
        );
        cargo.args(["--config", &fingerprint_cfg]);

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
