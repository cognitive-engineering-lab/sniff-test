#![feature(rustc_private)]

extern crate rustc_driver;
extern crate rustc_hir;
extern crate rustc_interface;
extern crate rustc_middle;

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use reachability::{
    NoopReachabilityHooks, ReachabilityGraph, ReachabilityIndex, ReachabilityNodeKind,
    ReachabilityOptions, ReachabilityRoot,
};
use rustc_driver::{Callbacks, Compilation};
use rustc_hir::def_id::LocalDefId;
use rustc_interface::interface;
use rustc_middle::ty::TyCtxt;
use sniff_test::config::{PanicConfig, PathPatterns};
use sniff_test::panics::{
    PanicEvidenceKind, PanicPathDecision, analyze_panic_evidence, describe_panic_evidence_kind,
};

#[test]
fn panic_axioms_are_raw_panic_evidence() {
    let report = analyze_source(
        r"
pub fn div(total_size: usize, block_count: usize) -> usize {
    total_size / block_count
}

pub fn rem(total_size: usize, block_size: usize) -> usize {
    total_size % block_size
}

pub fn index(slice: &[i32], i: usize) -> i32 {
    slice[i]
}

pub fn explicit() {
    panic!()
}

pub fn todo_panic() {
    todo!()
}

pub fn entry() {
    let values = [1];
    let _ = div(100, 1);
    let _ = rem(100, 1);
    let _ = index(&values, 0);
    explicit();
    todo_panic();
}
",
        "entry",
    );

    assert!(report.raw_panic_paths >= 5, "{report:#?}");
    assert_eq!(report.panic_obligations, Vec::<String>::new());
    assert_contains(&report.compiler_asserts, "DivisionByZero");
    assert_contains(&report.compiler_asserts, "RemainderByZero");
    assert_contains(&report.compiler_asserts, "BoundsCheck");
    assert_contains(&report.panic_sinks, "panic");
}

#[test]
fn panic_doc_headings_create_obligations() {
    let report = analyze_source(
        r"
/// # Panics
/// This function will panic.
pub fn func1() {
    panic!()
}

/// ## Panics
/// This function will panic.
pub fn func2() {
    panic!()
}

/// ### Panics
/// This function will panic.
pub fn func3() {
    panic!()
}

/// #### Panic(s)
/// This function will panic.
pub fn func4() {
    panic!()
}

/// # Panics
/// This function can panic.
pub fn spaces_after() {
    panic!();
}

/// # Panics        
/// This function can panic.
pub fn tabs_after() {
    panic!();
}

/// # Panics            	
/// This function can panic.
pub fn mix_after() {
    panic!();
}

pub fn entry() {
    func1();
    func2();
    func3();
    func4();
    spaces_after();
    tabs_after();
    mix_after();
}
",
        "entry",
    );

    assert_eq!(report.raw_panic_paths, 0, "{report:#?}");
    for function in [
        "func1",
        "func2",
        "func3",
        "func4",
        "spaces_after",
        "tabs_after",
        "mix_after",
    ] {
        assert_contains(&report.panic_obligations, function);
    }
}

#[test]
fn talk_example_reports_compiler_asserts() {
    let report = analyze_source(
        r"
pub fn chunk_slice(slice: &[usize], chunk_size: usize) -> Vec<&[usize]> {
    let num_chunks = slice.len() / chunk_size;
    let mut result = Vec::with_capacity(num_chunks);

    let mut start = 0;
    for _ in 0..num_chunks {
        let chunk = &slice[start..(start + chunk_size)];
        result.push(chunk);
        start += chunk_size;
    }

    result
}
",
        "chunk_slice",
    );

    assert!(report.raw_panic_paths > 0, "{report:#?}");
    assert_contains(&report.compiler_asserts, "DivisionByZero");
}

#[test]
fn generic_roots_report_compiler_asserts() {
    let report = analyze_source(
        r"
pub fn generic_index<T>(values: &[T], index: usize) -> &T {
    &values[index]
}
",
        "generic_index",
    );

    assert!(report.raw_panic_paths > 0, "{report:#?}");
    assert_contains(&report.compiler_asserts, "BoundsCheck");
}

#[test]
fn generic_roots_report_panic_obligations() {
    let report = analyze_source(
        r"
pub fn generic_split_at<T>(values: &[T], index: usize) -> &[T] {
    values.split_at(index).0
}
",
        "generic_split_at",
    );

    assert_eq!(report.raw_panic_paths, 0, "{report:#?}");
    assert_contains(&report.panic_obligations, "split_at");
}

#[derive(Debug, Default)]
struct PanicReport {
    raw_panic_paths: usize,
    panic_obligations: Vec<String>,
    compiler_asserts: Vec<String>,
    panic_sinks: Vec<String>,
}

fn analyze_source(source: &str, root_suffix: &str) -> PanicReport {
    let project = TempProject::new(source);
    let sysroot = rustc_sysroot();
    let mut callbacks = PanicCallbacks {
        root_suffix: root_suffix.to_owned(),
        config: panic_config(),
        report: None,
    };
    let args = vec![
        String::from("rustc"),
        String::from("--crate-name"),
        String::from("panic_case"),
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

    callbacks
        .report
        .unwrap_or_else(|| panic!("compiler callback did not analyze `{root_suffix}`"))
}

struct PanicCallbacks {
    root_suffix: String,
    config: PanicConfig,
    report: Option<PanicReport>,
}

impl Callbacks for PanicCallbacks {
    fn after_analysis(&mut self, _compiler: &interface::Compiler, tcx: TyCtxt<'_>) -> Compilation {
        let root = find_local_body(tcx, &self.root_suffix);
        let mut hooks = NoopReachabilityHooks;
        let mut index = ReachabilityIndex::new(tcx);
        let result = index.query(
            ReachabilityRoot::LocalBody(root),
            &mut hooks,
            ReachabilityOptions {
                node_limit: Some(256),
                analyze_external: false,
                ..ReachabilityOptions::default()
            },
        );
        let graph = index.graph();
        let analysis = analyze_panic_evidence(tcx, graph, &result, &self.config);
        let mut report = PanicReport::default();

        for evidence in &analysis.evidence {
            match &evidence.decision {
                PanicPathDecision::RawPanic => {
                    report.raw_panic_paths += 1;
                }
                PanicPathDecision::PanicObligation { def_id, .. } => {
                    report.panic_obligations.push(tcx.def_path_str(*def_id));
                }
            }

            match &evidence.kind {
                PanicEvidenceKind::CompilerAssert => {
                    report
                        .compiler_asserts
                        .push(compiler_assert_message(graph, evidence.edge_id));
                }
                PanicEvidenceKind::PanicObligation { .. } => {}
                PanicEvidenceKind::PanicSink { .. } => report
                    .panic_sinks
                    .push(describe_panic_evidence_kind(tcx, &evidence.kind)),
            }
        }

        self.report = Some(report);
        Compilation::Stop
    }
}

fn compiler_assert_message(
    graph: &ReachabilityGraph<'_>,
    edge_id: reachability::ReachabilityEdgeId,
) -> String {
    let edge = graph.edge(edge_id);
    match &graph.node(edge.target).kind {
        ReachabilityNodeKind::CompilerAssert { message } => format!("{message:?}"),
        node => panic!("expected compiler assert target, got {node:?}"),
    }
}

fn panic_config() -> PanicConfig {
    PanicConfig {
        panic_sink_namespaces: PathPatterns::new(vec![
            String::from("core::panicking::**"),
            String::from("std::panicking::**"),
            String::from("std::rt::panic_fmt"),
        ])
        .expect("panic sink patterns should compile"),
        ..PanicConfig::default()
    }
}

fn find_local_body(tcx: TyCtxt<'_>, suffix: &str) -> LocalDefId {
    tcx.hir_body_owners()
        .find(|local| tcx.def_path_str(local.to_def_id()).ends_with(suffix))
        .unwrap_or_else(|| panic!("could not find local body ending with `{suffix}`"))
}

fn assert_contains(values: &[String], needle: &str) {
    assert!(
        values.iter().any(|value| value.contains(needle)),
        "could not find `{needle}` in {values:#?}"
    );
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
        "sniff-test-panic-evidence-{}-{}",
        std::process::id(),
        nanos_since_epoch()
    ));
    assert!(
        !base.exists(),
        "temporary project path already exists: {}",
        base.display()
    );
    base
}

fn nanos_since_epoch() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is before unix epoch")
        .as_nanos()
}
