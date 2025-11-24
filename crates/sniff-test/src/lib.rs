//! A Rustc plugin that prints out the name of all items in a crate.

#![feature(rustc_private)]
#![feature(box_patterns)]
#![feature(try_trait_v2)]
#![cfg_attr(test, feature(assert_matches))]
#![deny(warnings)]
#![warn(clippy::pedantic)]
#![allow(
    unused,
    clippy::must_use_candidate,
    clippy::missing_panics_doc, // TODO: should remove this, kinda ironic for us to be using it...
    clippy::missing_errors_doc,
    clippy::needless_pass_by_value,
)]

extern crate lazy_static;
extern crate rustc_ast;
extern crate rustc_driver;
extern crate rustc_errors;
extern crate rustc_hir;
extern crate rustc_interface;
extern crate rustc_middle;
extern crate rustc_public;
extern crate rustc_query_system;
extern crate rustc_session;
extern crate rustc_span;
extern crate rustc_type_ir;

pub mod annotations;
mod check;
pub mod properties;
mod reachability;
pub mod utils;

use std::{borrow::Cow, env, process::Command};

use clap::Parser;
use rustc_hir::def_id::LOCAL_CRATE;
use rustc_middle::ty::TyCtxt;
use rustc_plugin::{CrateFilter, RustcPlugin, RustcPluginArgs, Utf8Path};
use serde::{Deserialize, Serialize};

use crate::check::check_crate_for_property;

// This struct is the plugin provided to the rustc_plugin framework,
// and it must be exported for use by the CLI/driver binaries.
pub struct PrintAllItemsPlugin;

// To parse CLI arguments, we use Clap for this example. But that
// detail is up to you.
#[derive(Parser, Serialize, Deserialize, Clone, Default)]
pub struct SniffTestArgs {
    #[arg(short, long)]
    allcaps: bool,

    #[arg(short, long)]
    release: bool,

    #[clap(last = true)]
    cargo_args: Vec<String>,
}

const TO_FILE: bool = true;

fn env_logger_init_file(driver: bool) {
    use std::fs::OpenOptions;
    use std::io::Write;

    let mut log_file_opts = OpenOptions::new();
    log_file_opts.write(true);

    if driver {
        log_file_opts.append(true);
    } else {
        log_file_opts.create(true).truncate(true);
    }

    let log_file = log_file_opts
        .open("sniff-test.log")
        .expect("Failed to open log file");

    env_logger::Builder::from_default_env()
        .format_timestamp(None)
        .target(env_logger::Target::Pipe(Box::new(log_file)))
        .init();
}

fn env_logger_init_terminal() {
    env_logger::Builder::from_default_env()
        .format_timestamp(None)
        .init();
}

pub fn env_logger_init(driver: bool) {
    if TO_FILE && !cfg!(debug_assertions) {
        env_logger_init_file(driver);
    } else {
        env_logger_init_terminal();
    }
}

impl RustcPlugin for PrintAllItemsPlugin {
    type Args = SniffTestArgs;

    fn version(&self) -> Cow<'static, str> {
        env!("CARGO_PKG_VERSION").into()
    }

    fn driver_name(&self) -> Cow<'static, str> {
        "sniff-test-driver".into()
    }

    // In the CLI, we ask Clap to parse arguments and also specify a CrateFilter.
    // If one of the CLI arguments was a specific file to analyze, then you
    // could provide a different filter.
    fn args(&self, _target_dir: &Utf8Path) -> RustcPluginArgs<Self::Args> {
        let args = SniffTestArgs::parse_from(env::args().skip(1));
        let filter = CrateFilter::AllCrates;
        RustcPluginArgs { args, filter }
    }

    // Pass Cargo arguments (like --feature) from the top-level CLI to Cargo.
    fn modify_cargo(&self, cargo: &mut Command, args: &Self::Args) {
        cargo.args(&args.cargo_args);

        if args.release {
            panic!(
                "release can inline some functions, so not sure if we want to allow this yet..."
            );
            cargo.args(["--release"]);
        }

        // Register the sniff_tool
        let existing = std::env::var("RUSTFLAGS").unwrap_or_default();
        cargo.env("RUSTFLAGS", format!("-Zcrate-attr=feature(register_tool) -Zcrate-attr=register_tool(sniff_tool) -Aunused-doc-comments {existing} -Zcrate-attr=feature(custom_inner_attributes)"));
    }

    // In the driver, we use the Rustc API to start a compiler session
    // for the arguments given to us by rustc_plugin.
    fn run(
        self,
        compiler_args: Vec<String>,
        plugin_args: Self::Args,
    ) -> rustc_interface::interface::Result<()> {
        let mut callbacks = PrintAllItemsCallbacks {
            args: Some(plugin_args),
        };

        rustc_driver::run_compiler(&compiler_args, &mut callbacks);
        Ok(())
    }
}

#[allow(dead_code)]
struct PrintAllItemsCallbacks {
    args: Option<SniffTestArgs>,
}

impl rustc_driver::Callbacks for PrintAllItemsCallbacks {
    // At the top-level, the Rustc API uses an event-based interface for
    // accessing the compiler at different stages of compilation. In this callback,
    // all the type-checking has completed.
    fn after_analysis(
        &mut self,
        _compiler: &rustc_interface::interface::Compiler,
        tcx: TyCtxt<'_>,
    ) -> rustc_driver::Compilation {
        let crate_name = tcx.crate_name(LOCAL_CRATE);

        log::debug!("checking crate {crate_name}");
        let Ok(()) = check_crate_for_property(tcx, properties::SafetyProperty) else {
            return rustc_driver::Compilation::Stop;
        };

        println!("the `{crate_name}` crate passes the sniff test!!");

        // Note that you should generally allow compilation to continue. If
        // your plugin is being invoked on a dependency, then you need to ensure
        // the dependency is type-checked (its .rmeta file is emitted into target/)
        // so that its dependents can read the compiler outputs.
        rustc_driver::Compilation::Continue
    }
}
