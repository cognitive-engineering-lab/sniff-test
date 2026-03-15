//! A Rustc plugin that prints out the name of all items in a crate.

#![feature(rustc_private)]
#![feature(iter_map_windows)]
#![feature(box_patterns)]
#![feature(try_trait_v2)]
#![cfg_attr(test, feature(assert_matches))]
#![deny(warnings)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::must_use_candidate,
    clippy::missing_panics_doc, // TODO: should remove this, kinda ironic for us to be using it...
    clippy::missing_errors_doc,
    clippy::needless_pass_by_value,
    clippy::result_large_err
)]

extern crate lazy_static;
extern crate rustc_ast;
extern crate rustc_driver;
extern crate rustc_errors;
extern crate rustc_hir;
extern crate rustc_index;
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
pub mod reachability;
pub mod utils;

use std::{borrow::Cow, env, process::Command, sync::Mutex};

use clap::{Parser, ValueEnum};
use rustc_hir::def_id::LOCAL_CRATE;
use rustc_middle::ty::TyCtxt;
use rustc_plugin::{CrateFilter, RustcPlugin, RustcPluginArgs, Utf8Path};
use rustc_span::ErrorGuaranteed;
use serde::{Deserialize, Serialize};

use crate::check::{CheckStats, check_crate_for_property, err::report_errors};

// This struct is the plugin provided to the rustc_plugin framework,
// and it must be exported for use by the CLI/driver binaries.
pub struct PrintAllItemsPlugin;

// To parse CLI arguments, we use Clap for this example. But that
// detail is up to you.
#[derive(Parser, Serialize, Deserialize, Default, Clone, Debug)]
pub struct SniffTestArgs {
    /// How to handle this workspace's dependencies.
    #[arg(short, long)]
    dependencies: DependenciesPosture,

    #[arg(short, long)]
    /// LEGACY ARG (i'm keeping it around to be faster, will remove later):
    /// whether or not dependencies have to have sniff-test formatted code comments.
    check_dependencies: bool,

    #[arg(short, long)]
    fine_grained: bool,

    #[arg(short, long)]
    buzzword_checking: bool,

    #[clap(last = true)]
    cargo_args: Vec<String>,
}

#[derive(ValueEnum, Clone, Debug, Default, Serialize, Deserialize)]
enum DependenciesPosture {
    #[default]
    /// Trust that dependencies have been properly documented with regard to the desired properties.
    ///
    /// *"I trust them"*
    Trust,
    /// Analyze the **used** public functions of all transitive dependencies, flagging potential issues
    /// to be fixed at the boundary of the current workspace.
    ///
    /// *"I don't care if their code is correct, I just want to make sure how I'm using it is fine."*
    Find,
    /// Analyze the public functions of all transitive dependencies, ensuring that they
    /// would pass the same analysis done on this workspace.
    ///
    /// *"Let's make sure their code is correct too."*
    Verify,
}

const TO_FILE: bool = false;

pub static ARGS: Mutex<Option<SniffTestArgs>> = Mutex::new(None);

fn env_logger_init_file(driver: bool) {
    use std::fs::OpenOptions;

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
        let args = SniffTestArgs::parse_from(env::args());
        let filter = CrateFilter::AllCrates;
        RustcPluginArgs { args, filter }
    }

    // Pass Cargo arguments (like --feature) from the top-level CLI to Cargo.
    fn modify_cargo(&self, cargo: &mut Command, args: &Self::Args) {
        log::debug!("modifying cargo args");
        cargo.args(&args.cargo_args);

        // if args.release {
        //     cargo.args(["--release"]);
        //     panic!(
        //         "release can inline some functions, so not sure if we want to allow this yet..."
        //     );
        // }

        // Register the sniff_tool
        let existing = std::env::var("RUSTFLAGS").unwrap_or_default();
        cargo.env("RUSTFLAGS", format!("-Zcrate-attr=feature(register_tool) -Zcrate-attr=register_tool(sniff_tool) -Aunused-doc-comments {existing} -Zcrate-attr=feature(custom_inner_attributes)"));

        // Point to the driver binary, not the cargo subcommand binary
        let driver = std::env::current_exe()
            .unwrap()
            .with_file_name("sniff-test-driver"); // <-- driver, not cargo-sniff-test
        cargo.env("RUSTC_WRAPPER", &driver);
        cargo.env_remove("RUSTC_WORKSPACE_WRAPPER");
    }

    // In the driver, we use the Rustc API to start a compiler session
    // for the arguments given to us by rustc_plugin.
    fn run(
        self,
        compiler_args: Vec<String>,
        plugin_args: Self::Args,
    ) -> rustc_interface::interface::Result<()> {
        // Set the args so we can access them from anywhere...
        *ARGS.lock().unwrap() = Some(plugin_args.clone());

        let mut callbacks = PrintAllItemsCallbacks {
            args: Some(plugin_args.clone()),
            is_dependency: is_dependency(&compiler_args),
        };

        rustc_driver::run_compiler(&compiler_args, &mut callbacks);
        Ok(())
    }
}

#[allow(dead_code)]
struct PrintAllItemsCallbacks {
    args: Option<SniffTestArgs>,
    is_dependency: bool,
}

/// Checks if a given compiler invocation is for compiling something outside the current workspace.
// TODO: right now this uses a silly hack with the args, but there's got to be a better way...
fn is_dependency(compiler_args: &[String]) -> bool {
    let typical_path_slot = &compiler_args[4];

    if !std::path::Path::new(typical_path_slot)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"))
    {
        // This is very bad, but if there's not a rust file in this slot, I think you're likely not being
        // ultimately invoked by cargo, so you can't be a dependency. I'm 110% sure I will be proven wrong about this
        // sometime and come back here to find this issue.
        return false;
    }

    // And this is very hacky, but library dependencies are installed in the .cargo/registry, so we can evilly
    // use whether the path is absolute to check if the crate to be compiled is from the registry and, thus,
    // must be a dependency.
    typical_path_slot
        .chars()
        .next()
        .map(|first| first == '/')
        .expect("shouldn't have an empty string here")
}

fn check_crate_for_all_properties(
    tcx: TyCtxt,
    is_dependency: bool,
) -> Result<Vec<CheckStats>, ErrorGuaranteed> {
    Ok(vec![
        check_crate_for_property(tcx, properties::SafetyProperty, is_dependency).map_err(
            |(callgraph, errors)| {
                report_errors(
                    tcx,
                    properties::SafetyProperty,
                    callgraph.add_reachability(errors),
                )
            },
        )?,
        check_crate_for_property(tcx, properties::PanicProperty, is_dependency).map_err(
            |(callgraph, errors)| {
                report_errors(
                    tcx,
                    properties::PanicProperty,
                    callgraph.add_reachability(errors),
                )
            },
        )?,
    ])
}

// FIXME: move to check submodule
fn analyze_crate(
    tcx: TyCtxt,
    crate_name: rustc_span::Symbol,
    is_dependency: bool,
    args: &SniffTestArgs,
) -> rustc_driver::Compilation {
    match (is_dependency, &args.dependencies) {
        // If we're not a dependency, or we are but we're verifying them -> run full analysis
        (false, _) | (true, DependenciesPosture::Verify) => {
            let Ok(stats) = check_crate_for_all_properties(tcx, is_dependency) else {
                println!("the {crate_name} crate FAILED the sniff test");
                return rustc_driver::Compilation::Stop;
            };

            println!(
                "the {crate_name:^20} crate passes the sniff test!! \t\t(stable id {:16x?}) - {:>5}",
                tcx.stable_crate_id(LOCAL_CRATE).as_u64(),
                if is_dependency { "dep" } else { "local" },
            );
            log::debug!("\tstats for `{crate_name}` are {stats:?}");
        }
        (true, DependenciesPosture::Find) => {
            // find property 'caveats'
            todo!("do check, but don't error. just write to file for later analysis");
        }
        (true, DependenciesPosture::Trust) => { /* Nothing to be done! We're trusting :) */ }
    }
    rustc_driver::Compilation::Continue
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

        // Note that you should generally allow compilation to continue. If
        // your plugin is being invoked on a dependency, then you need to ensure
        // the dependency is type-checked (its .rmeta file is emitted into target/)
        // so that its dependents can read the compiler outputs.
        analyze_crate(
            tcx,
            crate_name,
            self.is_dependency,
            self.args.as_ref().unwrap(),
        )
    }
}
