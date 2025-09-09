//! A Rustc plugin that prints out the name of all items in a crate.

#![feature(rustc_private)]
#![cfg_attr(test, feature(assert_matches))]

extern crate lazy_static;
extern crate rustc_driver;
extern crate rustc_errors;
extern crate rustc_hir;
extern crate rustc_interface;
extern crate rustc_middle;
extern crate rustc_public;
extern crate rustc_session;
extern crate rustc_span;

mod annotations;

use std::{borrow::Cow, env, process::Command};

use clap::Parser;
use rustc_hir::{
    Item,
    intravisit::{self, Visitor},
};
use rustc_middle::ty::TyCtxt;
use rustc_plugin::{CrateFilter, RustcPlugin, RustcPluginArgs, Utf8Path};
use rustc_public::{CrateDef, mir::Safety};
use serde::{Deserialize, Serialize};

use crate::annotations::parse_requirements;

// This struct is the plugin provided to the rustc_plugin framework,
// and it must be exported for use by the CLI/driver binaries.
pub struct PrintAllItemsPlugin;

// To parse CLI arguments, we use Clap for this example. But that
// detail is up to you.
#[derive(Parser, Serialize, Deserialize, Clone)]
pub struct PrintAllItemsPluginArgs {
    #[arg(short, long)]
    allcaps: bool,

    #[clap(last = true)]
    cargo_args: Vec<String>,
}

impl RustcPlugin for PrintAllItemsPlugin {
    type Args = PrintAllItemsPluginArgs;

    fn version(&self) -> Cow<'static, str> {
        env!("CARGO_PKG_VERSION").into()
    }

    fn driver_name(&self) -> Cow<'static, str> {
        "print-all-items-driver".into()
    }

    // In the CLI, we ask Clap to parse arguments and also specify a CrateFilter.
    // If one of the CLI arguments was a specific file to analyze, then you
    // could provide a different filter.
    fn args(&self, _target_dir: &Utf8Path) -> RustcPluginArgs<Self::Args> {
        let args = PrintAllItemsPluginArgs::parse_from(env::args().skip(1));
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

struct PrintAllItemsCallbacks {
    args: Option<PrintAllItemsPluginArgs>,
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
        rustc_public::rustc_internal::run(tcx, alex_test_analysis(tcx)).unwrap();
        // We call our top-level function with access to the type context `tcx` and the CLI arguments.
        print_all_items(tcx, self.args.take().unwrap());

        // Note that you should generally allow compilation to continue. If
        // your plugin is being invoked on a dependency, then you need to ensure
        // the dependency is type-checked (its .rmeta file is emitted into target/)
        // so that its dependents can read the compiler outputs.
        rustc_driver::Compilation::Continue
    }
}

/// Just runs the doc comment parsing on all funcitons marked `unsafe` in the crate
/// as a sanity test for my parser.
fn alex_test_analysis(tcx: TyCtxt) -> impl FnOnce() {
    move || {
        let items = rustc_public::all_local_items()
            .into_iter()
            .filter_map(|item| {
                if let Some((def, generics)) = item.ty().kind().fn_def()
                    && def.fn_sig().value.safety == Safety::Unsafe
                {
                    return Some((def, generics.clone()));
                }

                None
            })
            .collect::<Vec<_>>();

        for (def, _args) in items {
            let res = match parse_requirements(tcx, def.def_id()) {
                Err(err) => {
                    let internal_def_id = rustc_public::rustc_internal::internal(tcx, def.def_id());
                    err.diag(
                        tcx.dcx(),
                        &tcx.def_path_debug_str(internal_def_id),
                        tcx.get_all_attrs(internal_def_id),
                    )
                    .emit();
                    return;
                }
                Ok(res) => res,
            };
            println!("{:?} => {res:?}", def.0.name());
        }

        // println!("items are {items:?}");
    }
}

// The core of our analysis. Right now it just prints out a description of each item.
// I recommend reading the Rustc Development Guide to better understand which compiler APIs
// are relevant to whatever task you have.
fn print_all_items(tcx: TyCtxt, args: PrintAllItemsPluginArgs) {
    tcx.hir_visit_all_item_likes_in_crate(&mut PrintVisitor { args, tcx });
}

struct PrintVisitor<'tcx> {
    args: PrintAllItemsPluginArgs,
    tcx: TyCtxt<'tcx>,
}

impl<'tcx> Visitor<'tcx> for PrintVisitor<'tcx> {
    #[allow(clippy::semicolon_if_nothing_returned)]
    fn visit_item(&mut self, item: &'tcx Item<'tcx>) -> Self::Result {
        let mut msg = match item.kind.ident() {
            Some(ident) => format!(
                "There is an item \"{}\" of type \"{}\"",
                ident,
                self.tcx.def_descr(item.owner_id.to_def_id())
            ),
            None => format!(
                "There is an item of type \"{}\"",
                self.tcx.def_descr(item.owner_id.to_def_id())
            ),
        };
        if self.args.allcaps {
            msg = msg.to_uppercase();
        }
        println!("{msg}");

        intravisit::walk_item(self, item)
    }
}
