#![feature(rustc_private)]

extern crate rustc_driver;
extern crate rustc_hir;
extern crate rustc_interface;
extern crate rustc_middle;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use reachability::{
    NoopReachabilityHooks, ReachabilityGraph, ReachabilityNodeKind, ReachabilityOptions,
    ReachabilityRoot, analyze_reachability,
};
use rustc_driver::{Callbacks, Compilation};
use rustc_hir::def_id::LocalDefId;
use rustc_interface::interface;
use rustc_middle::ty::TyCtxt;

const DEMO_SOURCE: &str = r"
pub trait Worker {
    fn work(&self);
}

pub struct Foo;

impl Worker for Foo {
    fn work(&self) {
        leaf();
    }
}

pub fn leaf() {}

pub fn helper() {
    leaf();
}

pub fn generic<T: Worker>(value: T) {
    value.work();
}

pub fn entry(flag: bool, value: usize) {
    helper();
    generic(Foo);

    let closure = || helper();
    closure();

    let fp: fn() = helper;
    fp();

    let foo = Foo;
    let _obj: &dyn Worker = &foo;

    let _ = Some(value).map(|x| x + 1);
    let _ = value + 1;
    Err::<i32,_>(0).unwrap();
    assert!(flag);
}
";

#[test]
fn smoke_test_renders_reachability_graph_for_temp_crate() {
    let project = TempProject::new(DEMO_SOURCE);
    let sysroot = rustc_sysroot();
    let mut callbacks = DumpCallbacks::default();
    let args = vec![
        String::from("rustc"),
        String::from("--crate-name"),
        String::from("demo"),
        String::from("--crate-type"),
        String::from("lib"),
        String::from("--edition"),
        String::from("2024"),
        String::from("--sysroot"),
        sysroot,
        String::from("-Awarnings"),
        project.source.display().to_string(),
    ];

    rustc_driver::run_compiler(&args, &mut callbacks);

    let output = callbacks.output.expect("compiler callback did not run");
    println!("{output}");

    assert!(output.contains("root entry"));
    assert!(output.contains("DirectCall -> helper"));
    assert!(output.contains("DirectCall -> generic"));
    assert!(output.contains("DirectCall -> std::option::Option::<T>::map"));
    assert!(output.contains("DirectCall -> <Foo as Worker>::work"));
    assert!(output.contains("FnPointerReify -> helper"));
    assert!(output.contains("DynObjectCast -> dyn-cast"));
    assert!(output.contains("VTableEntry -> <Foo as Worker>::work"));
    assert!(output.contains("Assert -> assert"));
}

#[derive(Default)]
struct DumpCallbacks {
    output: Option<String>,
}

impl Callbacks for DumpCallbacks {
    fn after_analysis(&mut self, _compiler: &interface::Compiler, tcx: TyCtxt<'_>) -> Compilation {
        let entry = find_local_body(tcx, "entry");
        let mut hooks = NoopReachabilityHooks;
        let graph = analyze_reachability(
            tcx,
            ReachabilityRoot::LocalBody(entry),
            &mut hooks,
            ReachabilityOptions {
                node_limit: Some(96),
                ..ReachabilityOptions::default()
            },
        );

        self.output = Some(render_graph(tcx, &graph));
        Compilation::Stop
    }
}

fn find_local_body(tcx: TyCtxt<'_>, suffix: &str) -> LocalDefId {
    tcx.hir_body_owners()
        .find(|local| tcx.def_path_str(local.to_def_id()).ends_with(suffix))
        .unwrap_or_else(|| panic!("could not find local body ending with `{suffix}`"))
}

fn render_graph<'tcx>(tcx: TyCtxt<'tcx>, graph: &ReachabilityGraph<'tcx>) -> String {
    let mut lines = vec![format!(
        "root {}",
        render_node(tcx, &graph.nodes()[graph.root().index()].kind)
    )];

    for node in graph.nodes() {
        lines.push(format!(
            "node depth={} {}",
            node.depth,
            render_node(tcx, &node.kind)
        ));
    }

    for edge in graph.edges() {
        lines.push(format!(
            "edge {} --{:?} -> {}",
            render_node(tcx, &graph.nodes()[edge.source.index()].kind),
            edge.kind,
            render_node(tcx, &graph.nodes()[edge.target.index()].kind)
        ));
    }

    lines.sort();
    lines.join("\n")
}

fn render_node<'tcx>(tcx: TyCtxt<'tcx>, node: &ReachabilityNodeKind<'tcx>) -> String {
    match node {
        ReachabilityNodeKind::Instance(instance) => render_instance(tcx, *instance),
        ReachabilityNodeKind::CompilerAssert { message } => format!("assert {message:?}"),
        ReachabilityNodeKind::IndirectCall { callee_ty } => format!("indirect {callee_ty:?}"),
        ReachabilityNodeKind::DynObjectCast {
            source_ty,
            target_ty,
        } => {
            format!("dyn-cast {source_ty:?} as {target_ty:?}")
        }
    }
}

fn render_instance<'tcx>(tcx: TyCtxt<'tcx>, instance: rustc_middle::ty::Instance<'tcx>) -> String {
    tcx.def_path_str(instance.def_id())
}

fn rustc_sysroot() -> String {
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = Command::new(rustc)
        .args(["--print", "sysroot"])
        .output()
        .expect("failed to run rustc --print sysroot");

    assert!(
        output.status.success(),
        "rustc --print sysroot failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout)
        .expect("sysroot was not valid utf-8")
        .trim()
        .to_owned()
}

struct TempProject {
    root: PathBuf,
    source: PathBuf,
}

impl TempProject {
    fn new(source: &str) -> Self {
        let root = unique_temp_dir();
        let src = root.join("src");
        fs::create_dir_all(&src).expect("failed to create temp project src directory");
        let source_path = src.join("lib.rs");
        fs::write(&source_path, source).expect("failed to write temp project source");
        Self {
            root,
            source: source_path,
        }
    }
}

impl Drop for TempProject {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn unique_temp_dir() -> PathBuf {
    let mut base = std::env::temp_dir();
    base.push(format!(
        "reachability-smoke-{}-{}",
        std::process::id(),
        nanos_since_epoch()
    ));
    ensure_not_exists(&base);
    base
}

fn ensure_not_exists(path: &Path) {
    assert!(
        !path.exists(),
        "temporary project path already exists: {}",
        path.display()
    );
}

fn nanos_since_epoch() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is before unix epoch")
        .as_nanos()
}
