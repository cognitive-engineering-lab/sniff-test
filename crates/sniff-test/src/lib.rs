//! A Rustc plugin that prints out the name of all items in a crate.

#![feature(rustc_private)]
#![feature(box_patterns)]
#![cfg_attr(test, feature(assert_matches))]
#![deny(warnings)]
#![warn(clippy::pedantic)]
#![allow(
    unused,
    clippy::must_use_candidate,
    clippy::missing_panics_doc, // TODO: should remove this, kinda ironic for us to be using it...
    clippy::missing_errors_doc
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
mod axioms;
mod check;
mod reachability;
pub mod utils;

use std::{borrow::Cow, env, process::Command};

use clap::Parser;
use rustc_middle::ty::TyCtxt;
use rustc_plugin::{CrateFilter, RustcPlugin, RustcPluginArgs, Utf8Path};
use serde::{Deserialize, Serialize};

use crate::check::check_properly_annotated;

// This struct is the plugin provided to the rustc_plugin framework,
// and it must be exported for use by the CLI/driver binaries.
pub struct PrintAllItemsPlugin;

// To parse CLI arguments, we use Clap for this example. But that
// detail is up to you.
#[derive(Parser, Serialize, Deserialize, Clone, Default)]
pub struct SniffTestArgs {
    #[arg(short, long)]
    allcaps: bool,

    #[clap(last = true)]
    cargo_args: Vec<String>,
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
        let Ok(()) = check_properly_annotated(tcx) else {
            return rustc_driver::Compilation::Stop;
        };

        println!("compilation successful!!");

        // Note that you should generally allow compilation to continue. If
        // your plugin is being invoked on a dependency, then you need to ensure
        // the dependency is type-checked (its .rmeta file is emitted into target/)
        // so that its dependents can read the compiler outputs.
        rustc_driver::Compilation::Continue
    }
}
