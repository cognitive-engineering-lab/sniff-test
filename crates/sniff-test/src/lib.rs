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

use std::{borrow::Cow, collections::HashMap, env, process::Command};

use clap::Parser;
use rustc_hir::{
    ExprKind, HirId, Item, Node,
    def_id::DefId,
    intravisit::{self, Visitor},
};
use rustc_middle::ty::TyCtxt;
use rustc_plugin::{CrateFilter, RustcPlugin, RustcPluginArgs, Utf8Path};
use rustc_public::CrateDef;
use rustc_span::ErrorGuaranteed;
use serde::{Deserialize, Serialize};

use crate::annotations::{Annotation, Justification, ParsingError, Requirement};

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
        "sniff-test-driver".into()
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

#[allow(dead_code)]
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
        let Ok(reqs) = rustc_public::rustc_internal::run(tcx, requirement_pass(tcx))
            .expect("rustc public should work i hope...")
        else {
            return rustc_driver::Compilation::Stop;
        };

        println!("reqs are {reqs:?}");

        let fns_to_track: &[DefId] = &reqs.keys().copied().collect::<Box<[_]>>();

        let Ok(justs) = justification_pass(tcx, fns_to_track)() else {
            return rustc_driver::Compilation::Stop;
        };

        println!("justs are {justs:?}");

        // Note that you should generally allow compilation to continue. If
        // your plugin is being invoked on a dependency, then you need to ensure
        // the dependency is type-checked (its .rmeta file is emitted into target/)
        // so that its dependents can read the compiler outputs.
        rustc_driver::Compilation::Continue
    }
}

type RequirementInfo = HashMap<DefId, Vec<Requirement>>;
/// Parses all functions that pass the given [`should_analyze_item`] predicate,
/// returning the [`Requirement`]s for those that have them.
fn requirement_pass(tcx: TyCtxt) -> impl FnOnce() -> Result<RequirementInfo, ErrorGuaranteed> {
    move || {
        rustc_public::all_local_items()
            .into_iter()
            // filter by items we should analyze
            .filter_map(|crate_def| should_analyze_item(crate_def, tcx))
            // try to analyze all `FnDef`s, but some will return `None` as they have no annotations...
            .filter_map(|def| {
                let internal_def = rustc_public::rustc_internal::internal(tcx, def.def_id());
                Some(
                    Requirement::try_parse(tcx, internal_def)?
                        .map(|reqs| (internal_def, reqs))
                        .map_err(|err| err.emit(tcx.dcx())),
                )
            })
            // collect into a hash map
            .collect::<Result<HashMap<_, _>, ErrorGuaranteed>>()
    }
}

type JustificationInfo = HashMap<HirId, Vec<Justification>>;

/// Records the [`Justification`]s given on all function calls to `fns_to_track`.
fn justification_pass(
    tcx: TyCtxt,
    fns_to_track: &[DefId],
) -> impl FnOnce() -> Result<JustificationInfo, ErrorGuaranteed> {
    move || {
        println!("gonna visit... w/ fns to track {fns_to_track:?}");
        let mut visitor = FnCallVisitor::new(tcx, fns_to_track);
        tcx.hir_visit_all_item_likes_in_crate(&mut visitor);
        visitor.finish()
    }
}

struct FnCallVisitor<'tcx, 'a> {
    tcx: TyCtxt<'tcx>,
    fns_to_track: &'a [DefId],
    results: HashMap<HirId, Result<Vec<Justification>, ErrorGuaranteed>>,
}

impl<'tcx, 'a> FnCallVisitor<'tcx, 'a> {
    fn new(tcx: TyCtxt<'tcx>, fns_to_track: &'a [DefId]) -> Self {
        Self {
            tcx,
            fns_to_track,
            results: HashMap::default(),
        }
    }

    /// Checks if we should try to analyze a function call to a given `DefId`.
    fn should_analyze_fn_call_to(&self, def_id: rustc_span::def_id::DefId) -> bool {
        self.fns_to_track.contains(&def_id)
    }

    /// Try to get the annotations from all parent code blocks for a given [`Expr`].
    ///
    /// This is used to ensure code like the following will work, even if
    /// the annotation isn't on the exact HIR node of the function call:
    /// ```
    /// # let foo = |ptr: &i32| *ptr;
    /// # let val = 42;
    /// # let ptr: &i32 = &val;
    /// /// Safety:
    /// /// - non-null: the ptr is non null
    /// unsafe { foo(ptr); }
    /// ```
    fn try_get_from_parent_blocks(
        &self,
        ex: &'tcx rustc_hir::Expr<'tcx>,
    ) -> Option<Result<Vec<Justification>, ParsingError<'_>>> {
        // TODO: stop looking once we reach a single code block, to ensure we don't
        self.tcx
            .hir_parent_iter(ex.hir_id)
            .filter_map(|(_id, node)| {
                if let Node::Expr(expr) = node
                    && let ExprKind::Block(..) = expr.kind
                {
                    Some(expr)
                } else {
                    None
                }
            })
            .find_map(|expr| Justification::try_parse(self.tcx, expr))
    }

    /// Consume this visitor and return the stored mapping between function call sites
    /// and the justifications behind them.
    fn finish(self) -> Result<HashMap<HirId, Vec<Justification>>, ErrorGuaranteed> {
        self.results
            .into_iter()
            .map(|(id, res)| res.map(|res| (id, res)))
            .collect()
    }
}

impl<'tcx> rustc_hir::intravisit::Visitor<'tcx> for FnCallVisitor<'tcx, '_> {
    // Have to set this to ensure we visit the expressions INSIDE function bodies.
    type NestedFilter = rustc_middle::hir::nested_filter::OnlyBodies;

    fn maybe_tcx(&mut self) -> Self::MaybeTyCtxt {
        self.tcx
    }

    fn visit_expr(&mut self, ex: &'tcx rustc_hir::Expr<'tcx>) -> Self::Result {
        if let rustc_hir::ExprKind::Call(f, _args) = ex.kind
            && let rustc_hir::ExprKind::Path(rustc_hir::QPath::Resolved(_self, path)) = f.kind
        {
            let def_id = path.res.def_id();

            if self.should_analyze_fn_call_to(def_id) {
                let annotation_res = Justification::try_parse(self.tcx, ex).unwrap_or_else(|| {
                    // try getting from parents
                    self.try_get_from_parent_blocks(ex).map_or_else(
                        || {
                            // if that fails, just return the original issue
                            Justification::parse(self.tcx, ex)
                        },
                        // update the span if we found it from a parent,
                        |found| {
                            found.map_err(|mut err| {
                                err.update_span(ex.span);
                                err
                            })
                        },
                    )
                });

                let res = annotation_res.map_err(|err| err.emit(self.tcx.dcx()));

                self.results.insert(ex.hir_id, res);
            }
        }

        intravisit::walk_expr(self, ex);
    }
}

fn should_analyze_item(
    item: rustc_public::CrateItem,
    _tcx: TyCtxt,
) -> Option<rustc_public::ty::FnDef> {
    if let Some((def, _generics)) = item.ty().kind().fn_def()
    // && def.fn_sig().value.safety == Safety::Unsafe
    {
        Some(def)
    } else {
        None
    }
}

// The core of our analysis. Right now it just prints out a description of each item.
// I recommend reading the Rustc Development Guide to better understand which compiler APIs
// are relevant to whatever task you have.
#[allow(dead_code)]
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
