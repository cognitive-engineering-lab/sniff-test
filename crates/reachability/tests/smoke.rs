#![feature(rustc_private)]

extern crate rustc_driver;
extern crate rustc_hir;
extern crate rustc_interface;
extern crate rustc_middle;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use reachability::{
    ArtifactScope, DynDispatchVTableEdges, FnPointerEdges, MirBodyLocation, NoopReachabilityHooks,
    ReachabilityEdgeKind, ReachabilityGraph, ReachabilityHooks, ReachabilityIndex,
    ReachabilityNodeExpansion, ReachabilityNodeKind, ReachabilityOptions, ReachabilityRoot,
    ReachabilitySnapshot,
};
use rustc_driver::{Callbacks, Compilation};
use rustc_hir::def_id::LocalDefId;
use rustc_interface::interface;
use rustc_middle::ty::{GenericArgs, Instance, InstanceKind, TyCtxt};

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

pub trait Inspector {
    fn inspect<T: ?Sized>(&self, value: &T);
}

impl Inspector for Foo {
    fn inspect<T: ?Sized>(&self, _value: &T) {
        leaf();
    }
}

pub trait PanickingWorker {
    fn panic_work(&self);
}

pub struct PanickingFoo;

impl PanickingWorker for PanickingFoo {
    fn panic_work(&self) {
        leaf();
    }
}

pub trait SafeWorker {
    fn safe_work(&self);
}

pub struct SafeFoo;

impl SafeWorker for SafeFoo {
    fn safe_work(&self) {
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
    let obj: &dyn Worker = &foo;
    obj.work();

    let _ = Some(value).map(|x| x + 1);
    let _ = value + 1;
    Err::<i32,_>(0).unwrap();
    assert!(flag);
}

pub fn generic_dyn<T: std::fmt::Debug>(value: &T) {
    let _obj: &dyn std::fmt::Debug = value;
}

pub fn generic_dyn_argument() {
    let foo = Foo;
    let obj: &dyn Worker = &foo;
    foo.inspect(obj);
}

pub fn mixed_dyn_traits() {
    let panicking = PanickingFoo;
    let _panicking_obj: &dyn PanickingWorker = &panicking;

    let safe = SafeFoo;
    let safe_obj: &dyn SafeWorker = &safe;
    safe_obj.safe_work();
}

pub struct OtherFoo;

impl Worker for OtherFoo {
    fn work(&self) {}
}

pub trait SuperWorker {
    fn super_work(&self);
}

pub trait SubWorker: SuperWorker {}

pub struct SubFoo;

impl SuperWorker for SubFoo {
    fn super_work(&self) {}
}

impl SubWorker for SubFoo {}

pub fn supertrait_dyn_dispatch() {
    let obj: &dyn SubWorker = &SubFoo;
    obj.super_work();
}

pub fn mixed_same_dyn_trait() {
    let panicking = Foo;
    let _panicking_obj: &dyn Worker = &panicking;

    let safe = OtherFoo;
    let safe_obj: &dyn Worker = &safe;
    safe_obj.work();
}

pub fn generic_const<const N: usize, T: Copy + Default>() -> [T; N] {
    let _ = const { N };
    [T::default(); N]
}
";

const SHARED_CALLABLE_SOURCE: &str = r"
pub fn fn_target() {}

pub fn expose_fn_target() -> fn() {
    fn_target
}

pub fn call_fn_target(target: fn()) {
    target();
}

pub fn call_known_fn_target() {
    let target: fn() = fn_target;
    target();
}

pub trait Worker {
    fn work(&self);
}

pub struct Foo;

impl Worker for Foo {
    fn work(&self) {}
}

static FOO: Foo = Foo;

pub fn expose_dyn_target() -> &'static dyn Worker {
    &FOO
}

pub fn call_dyn_target(target: &dyn Worker) {
    target.work();
}
";

const EXPANDED_LEAF_SOURCE: &str = r"
pub fn entry() {
    leaf();
}

fn leaf() {}

pub fn external_entry() {
    std::process::abort();
}
";

const DUPLICATED_ASSERT_SOURCE: &str = r"
macro_rules! duplicate {
    ($expression:expr) => {
        ($expression, $expression)
    };
}

#[inline(never)]
fn select(values: &[u8]) -> &[u8] {
    values
}

pub fn entry(values: &[u8], index: usize) -> (u8, u8) {
    duplicate!(select(values)[index])
}
";

#[test]
fn smoke_test_renders_reachability_graph_for_temp_crate() {
    let project = TempProject::new(DEMO_SOURCE);
    let mut callbacks = DumpCallbacks::default();
    run_test_compiler(&project, &mut callbacks);

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
    assert!(!output.contains("DynDispatchVTableEntry -> <Foo as Worker>::work"));
    assert!(output.contains("Assert -> assert"));
}

#[test]
fn dyn_dispatch_vtable_edges_can_be_attributed_to_call_sites() {
    let project = TempProject::new(DEMO_SOURCE);
    let mut callbacks = DumpCallbacks {
        dyn_dispatch_vtable_edges: DynDispatchVTableEdges::CallSites,
        ..DumpCallbacks::default()
    };
    run_test_compiler(&project, &mut callbacks);

    let output = callbacks.output.expect("compiler callback did not run");
    println!("{output}");

    assert!(output.contains("edge entry --DynObjectCast -> dyn-cast"));
    assert!(!output.contains("edge entry --VTableEntry -> <Foo as Worker>::work"));
    assert_eq!(
        output
            .matches("edge entry --DynDispatchVTableEntry -> <Foo as Worker>::work")
            .count(),
        1,
        "each dynamic-dispatch target should be emitted exactly once"
    );
}

#[test]
fn function_pointer_edges_can_be_attributed_to_call_sites() {
    let project = TempProject::new(DEMO_SOURCE);
    let mut callbacks = DumpCallbacks {
        fn_pointer_edges: FnPointerEdges::CallSites,
        ..DumpCallbacks::default()
    };
    run_test_compiler(&project, &mut callbacks);

    let output = callbacks.output.expect("compiler callback did not run");
    println!("{output}");

    assert!(!output.contains("edge entry --FnPointerReify -> helper"));
    assert_eq!(
        output
            .matches("edge entry --FnPointerCallTarget -> helper")
            .count(),
        1,
        "each function-pointer target should be emitted exactly once"
    );
}

#[test]
fn dyn_dispatch_call_sites_match_supertrait_vtable_entries() {
    let project = TempProject::new(DEMO_SOURCE);
    let mut callbacks = DumpCallbacks {
        root_suffix: String::from("supertrait_dyn_dispatch"),
        dyn_dispatch_vtable_edges: DynDispatchVTableEdges::CallSites,
        ..DumpCallbacks::default()
    };
    run_test_compiler(&project, &mut callbacks);

    let output = callbacks.output.expect("compiler callback did not run");
    println!("{output}");

    assert_eq!(
        output
            .matches(
                "edge supertrait_dyn_dispatch --DynDispatchVTableEntry -> \
                 <SubFoo as SuperWorker>::super_work",
            )
            .count(),
        1,
        "a dyn subtrait call should reach its supertrait implementation once"
    );
}

#[test]
fn generic_trait_bound_calls_are_indirect_boundaries() {
    let project = TempProject::new(DEMO_SOURCE);
    let mut callbacks = DumpCallbacks {
        root_suffix: String::from("generic"),
        ..DumpCallbacks::default()
    };
    run_test_compiler(&project, &mut callbacks);

    let output = callbacks.output.expect("compiler callback did not run");
    println!("{output}");

    assert!(output.contains("root generic"));
    assert!(output.contains("IndirectCall -> indirect"));
    assert!(!output.contains("DirectCall -> <Foo as Worker>::work"));
}

#[test]
fn generic_dyn_casts_do_not_resolve_vtable_entries() {
    let project = TempProject::new(DEMO_SOURCE);
    let mut callbacks = DumpCallbacks {
        root_suffix: String::from("generic_dyn"),
        ..DumpCallbacks::default()
    };
    run_test_compiler(&project, &mut callbacks);

    let output = callbacks.output.expect("compiler callback did not run");
    println!("{output}");

    assert!(output.contains("root generic_dyn"));
    assert!(output.contains("DynObjectCast -> dyn-cast"));
    assert!(!output.contains("VTableEntry ->"));
}

#[test]
fn dyn_type_arguments_do_not_imply_dynamic_dispatch() {
    let project = TempProject::new(DEMO_SOURCE);
    let mut callbacks = DumpCallbacks {
        root_suffix: String::from("generic_dyn_argument"),
        dyn_dispatch_vtable_edges: DynDispatchVTableEdges::CallSites,
        ..DumpCallbacks::default()
    };
    run_test_compiler(&project, &mut callbacks);

    let output = callbacks.output.expect("compiler callback did not run");
    println!("{output}");

    assert!(output.contains("root generic_dyn_argument"));
    assert!(output.contains("edge generic_dyn_argument --DynObjectCast -> dyn-cast"));
    assert!(!output.contains("DynDispatchVTableEntry ->"));
}

#[test]
fn call_site_vtable_edges_are_filtered_to_the_called_trait() {
    let project = TempProject::new(DEMO_SOURCE);
    let mut callbacks = DumpCallbacks {
        root_suffix: String::from("mixed_dyn_traits"),
        dyn_dispatch_vtable_edges: DynDispatchVTableEdges::CallSites,
        ..DumpCallbacks::default()
    };
    run_test_compiler(&project, &mut callbacks);

    let output = callbacks.output.expect("compiler callback did not run");
    println!("{output}");

    assert!(output.contains("root mixed_dyn_traits"));
    assert!(output.contains("DynDispatchVTableEntry -> <SafeFoo as SafeWorker>::safe_work"));
    assert!(
        !output.contains("DynDispatchVTableEntry -> <PanickingFoo as PanickingWorker>::panic_work")
    );
}

#[test]
fn call_site_vtable_edges_are_trait_wide_within_a_body() {
    let project = TempProject::new(DEMO_SOURCE);
    let mut callbacks = DumpCallbacks {
        root_suffix: String::from("mixed_same_dyn_trait"),
        dyn_dispatch_vtable_edges: DynDispatchVTableEdges::CallSites,
        ..DumpCallbacks::default()
    };
    run_test_compiler(&project, &mut callbacks);

    let output = callbacks.output.expect("compiler callback did not run");
    println!("{output}");

    assert!(output.contains("root mixed_same_dyn_trait"));
    assert!(output.contains("DynDispatchVTableEntry -> <Foo as Worker>::work"));
    assert!(output.contains("DynDispatchVTableEntry -> <OtherFoo as Worker>::work"));
}

#[test]
fn generic_const_bodies_do_not_instantiate_with_parent_args() {
    let project = TempProject::new(DEMO_SOURCE);
    let mut callbacks = DumpCallbacks {
        root_suffix: String::from("generic_const"),
        ..DumpCallbacks::default()
    };
    run_test_compiler(&project, &mut callbacks);

    let output = callbacks.output.expect("compiler callback did not run");
    println!("{output}");

    assert!(output.contains("root generic_const"));
    assert!(output.contains("ConstBody ->"));
}

#[test]
fn function_pointer_targets_are_reused_across_queries() {
    let project = TempProject::new(SHARED_CALLABLE_SOURCE);
    let mut callbacks = SharedCallableCallbacks {
        scenario: SharedCallableScenario::FunctionPointerReuse,
        result: None,
    };
    run_test_compiler(&project, &mut callbacks);

    assert_eq!(callbacks.result, Some(1));
}

#[test]
fn dyn_dispatch_targets_are_reused_across_queries() {
    let project = TempProject::new(SHARED_CALLABLE_SOURCE);
    let mut callbacks = SharedCallableCallbacks {
        scenario: SharedCallableScenario::DynDispatchReuse,
        result: None,
    };
    run_test_compiler(&project, &mut callbacks);

    assert_eq!(callbacks.result, Some(1));
}

#[test]
fn multi_root_query_discovers_callable_targets_independent_of_root_order() {
    let project = TempProject::new(SHARED_CALLABLE_SOURCE);
    let mut callbacks = SharedCallableCallbacks {
        scenario: SharedCallableScenario::MultiRootCallableDiscovery,
        result: None,
    };
    run_test_compiler(&project, &mut callbacks);

    assert_eq!(
        callbacks.result,
        Some(4),
        "both roots and both callable target kinds should share one traversal snapshot"
    );
}

#[test]
fn same_kind_same_span_assertions_have_distinct_deterministic_mir_sites() {
    let project = TempProject::new(DUPLICATED_ASSERT_SOURCE);
    let mut callbacks = CompilerAssertSiteCallbacks { result: None };
    run_test_compiler(&project, &mut callbacks);

    let result = callbacks.result.expect("compiler callback did not run");
    assert_ne!(result.first_run[0], result.first_run[1]);
    assert_eq!(result.first_run, result.second_run);
}

#[test]
fn expanded_leaf_is_not_a_frontier() {
    let project = TempProject::new(EXPANDED_LEAF_SOURCE);
    let mut callbacks = LocalExpansionCallbacks { result: None };
    run_test_compiler(&project, &mut callbacks);
    let result = callbacks.result.expect("compiler callback did not run");

    assert_eq!(
        (
            result.leaf_expansion,
            result.leaf_outgoing_edges,
            result.leaf_is_frontier,
        ),
        (ReachabilityNodeExpansion::Expanded, 0, false)
    );
}

#[test]
fn artifact_scope_distinguishes_crossings_from_unavailable_mir() {
    let project = TempProject::new(EXPANDED_LEAF_SOURCE);
    let mut callbacks = ArtifactScopeCallbacks { result: None };
    run_test_compiler(&project, &mut callbacks);

    assert_eq!(
        callbacks.result,
        Some(ArtifactScopeResult {
            root_artifact: ReachabilityNodeExpansion::DifferentArtifact,
            all_artifacts: ReachabilityNodeExpansion::MirUnavailable,
        })
    );
}

#[test]
fn policy_boundary_and_node_limit_are_explicit_frontiers() {
    let project = TempProject::new(EXPANDED_LEAF_SOURCE);
    let mut callbacks = LocalExpansionCallbacks { result: None };
    run_test_compiler(&project, &mut callbacks);
    let result = callbacks.result.expect("compiler callback did not run");

    assert_eq!(
        (
            result.policy_boundary,
            result.node_limit,
            result.unsupported_instance,
        ),
        (
            ReachabilityNodeExpansion::PolicyBoundary,
            ReachabilityNodeExpansion::NodeLimit,
            ReachabilityNodeExpansion::UnsupportedInstance,
        )
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ArtifactScopeResult {
    root_artifact: ReachabilityNodeExpansion,
    all_artifacts: ReachabilityNodeExpansion,
}

struct ArtifactScopeCallbacks {
    result: Option<ArtifactScopeResult>,
}

#[derive(Debug, PartialEq, Eq)]
struct CompilerAssertSiteResult {
    first_run: Vec<MirBodyLocation>,
    second_run: Vec<MirBodyLocation>,
}

struct CompilerAssertSiteCallbacks {
    result: Option<CompilerAssertSiteResult>,
}

impl Callbacks for CompilerAssertSiteCallbacks {
    fn after_analysis(&mut self, _compiler: &interface::Compiler, tcx: TyCtxt<'_>) -> Compilation {
        let first_run = compiler_assert_sites(tcx);
        let second_run = compiler_assert_sites(tcx);
        self.result = Some(CompilerAssertSiteResult {
            first_run,
            second_run,
        });
        Compilation::Stop
    }
}

fn compiler_assert_sites(tcx: TyCtxt<'_>) -> Vec<MirBodyLocation> {
    let entry = ReachabilityRoot::LocalBody(find_local_body(tcx, "entry"));
    let mut index = ReachabilityIndex::new(tcx);
    let snapshot = index.query(
        entry,
        &NoopReachabilityHooks,
        ReachabilityOptions::default(),
    );
    let view = index.graph().view(&snapshot);
    let assertions = view
        .edges()
        .filter_map(|edge| {
            let ReachabilityNodeKind::CompilerAssert { message, site, .. } = edge.target().kind()
            else {
                return None;
            };
            Some((*site, edge.span(), std::mem::discriminant(message.as_ref())))
        })
        .collect::<Vec<_>>();

    assert_eq!(assertions.len(), 2);
    assert_eq!(assertions[0].1, assertions[1].1);
    assert_eq!(assertions[0].2, assertions[1].2);
    assertions.into_iter().map(|(site, _, _)| site).collect()
}

impl Callbacks for ArtifactScopeCallbacks {
    fn after_analysis(&mut self, _compiler: &interface::Compiler, tcx: TyCtxt<'_>) -> Compilation {
        let entry = ReachabilityRoot::LocalBody(find_local_body(tcx, "external_entry"));
        let root_artifact = expansion_for_target(
            tcx,
            entry,
            ReachabilityOptions {
                artifact_scope: ArtifactScope::RootArtifact,
                ..ReachabilityOptions::default()
            },
            "process::abort",
        );
        let all_artifacts =
            expansion_for_target(tcx, entry, ReachabilityOptions::default(), "process::abort");
        self.result = Some(ArtifactScopeResult {
            root_artifact,
            all_artifacts,
        });
        Compilation::Stop
    }
}

fn expansion_for_target<'tcx>(
    tcx: TyCtxt<'tcx>,
    root: ReachabilityRoot<'tcx>,
    options: ReachabilityOptions,
    suffix: &str,
) -> ReachabilityNodeExpansion {
    let mut index = ReachabilityIndex::new(tcx);
    let hooks = NoopReachabilityHooks;
    let snapshot = index.query(root, &hooks, options);
    index
        .graph()
        .view(&snapshot)
        .nodes()
        .find_map(|node| {
            let instance = node.instance()?;
            tcx.def_path_str(instance.def_id())
                .ends_with(suffix)
                .then(|| node.expansion())
                .flatten()
        })
        .unwrap_or_else(|| panic!("target ending with `{suffix}` was not reached"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LocalExpansionResult {
    leaf_expansion: ReachabilityNodeExpansion,
    leaf_outgoing_edges: usize,
    leaf_is_frontier: bool,
    policy_boundary: ReachabilityNodeExpansion,
    node_limit: ReachabilityNodeExpansion,
    unsupported_instance: ReachabilityNodeExpansion,
}

struct LocalExpansionCallbacks {
    result: Option<LocalExpansionResult>,
}

impl Callbacks for LocalExpansionCallbacks {
    fn after_analysis(&mut self, _compiler: &interface::Compiler, tcx: TyCtxt<'_>) -> Compilation {
        let root = ReachabilityRoot::LocalBody(find_local_body(tcx, "entry"));
        let mut index = ReachabilityIndex::new(tcx);
        let hooks = NoopReachabilityHooks;
        let snapshot = index.query(
            root,
            &hooks,
            ReachabilityOptions {
                artifact_scope: ArtifactScope::RootArtifact,
                ..ReachabilityOptions::default()
            },
        );
        let view = index.graph().view(&snapshot);
        let leaf = view
            .nodes()
            .find(|node| {
                node.instance()
                    .is_some_and(|instance| tcx.def_path_str(instance.def_id()).ends_with("leaf"))
            })
            .expect("leaf was not reached");
        let leaf_expansion = leaf.expansion().expect("leaf is an instance");
        let leaf_outgoing_edges = view.outgoing_edges(leaf.id()).count();
        let leaf_is_frontier = view.frontier().any(|node| node.id() == leaf.id());

        let mut policy_index = ReachabilityIndex::new(tcx);
        let policy_hooks = RejectLeafHooks;
        let policy_snapshot = policy_index.query(
            root,
            &policy_hooks,
            ReachabilityOptions {
                artifact_scope: ArtifactScope::RootArtifact,
                ..ReachabilityOptions::default()
            },
        );
        let policy_boundary = policy_index
            .graph()
            .view(&policy_snapshot)
            .frontier()
            .find_map(|node| {
                let instance = node.instance()?;
                tcx.def_path_str(instance.def_id())
                    .ends_with("leaf")
                    .then(|| node.expansion())
                    .flatten()
            })
            .expect("policy-boundary leaf was not reached");

        let node_limit = expansion_for_target(
            tcx,
            root,
            ReachabilityOptions {
                node_limit: Some(1),
                artifact_scope: ArtifactScope::RootArtifact,
                ..ReachabilityOptions::default()
            },
            "leaf",
        );
        let unsupported_root = ReachabilityRoot::Instance(Instance {
            def: InstanceKind::Intrinsic(find_local_body(tcx, "entry").to_def_id()),
            args: GenericArgs::empty(),
        });
        let unsupported_instance = expansion_for_target(
            tcx,
            unsupported_root,
            ReachabilityOptions {
                artifact_scope: ArtifactScope::RootArtifact,
                ..ReachabilityOptions::default()
            },
            "entry",
        );
        self.result = Some(LocalExpansionResult {
            leaf_expansion,
            leaf_outgoing_edges,
            leaf_is_frontier,
            policy_boundary,
            node_limit,
            unsupported_instance,
        });
        Compilation::Stop
    }
}

struct RejectLeafHooks;

impl<'tcx> ReachabilityHooks<'tcx> for RejectLeafHooks {
    fn should_descend(&self, tcx: TyCtxt<'tcx>, target: rustc_middle::ty::Instance<'tcx>) -> bool {
        !tcx.def_path_str(target.def_id()).ends_with("leaf")
    }
}

struct DumpCallbacks {
    root_suffix: String,
    dyn_dispatch_vtable_edges: DynDispatchVTableEdges,
    fn_pointer_edges: FnPointerEdges,
    output: Option<String>,
}

impl Default for DumpCallbacks {
    fn default() -> Self {
        Self {
            root_suffix: String::from("entry"),
            dyn_dispatch_vtable_edges: DynDispatchVTableEdges::CastSites,
            fn_pointer_edges: FnPointerEdges::ReifySites,
            output: None,
        }
    }
}

impl Callbacks for DumpCallbacks {
    fn after_analysis(&mut self, _compiler: &interface::Compiler, tcx: TyCtxt<'_>) -> Compilation {
        let entry = find_local_body(tcx, &self.root_suffix);
        let hooks = NoopReachabilityHooks;
        let mut index = ReachabilityIndex::new(tcx);
        let result = index.query(
            ReachabilityRoot::LocalBody(entry),
            &hooks,
            ReachabilityOptions {
                node_limit: Some(96),
                dyn_dispatch_vtable_edges: self.dyn_dispatch_vtable_edges,
                fn_pointer_edges: self.fn_pointer_edges,
                ..ReachabilityOptions::default()
            },
        );

        self.output = Some(render_graph(tcx, index.graph(), &result));
        Compilation::Stop
    }
}

#[derive(Clone, Copy)]
enum SharedCallableScenario {
    FunctionPointerReuse,
    DynDispatchReuse,
    MultiRootCallableDiscovery,
}

struct SharedCallableCallbacks {
    scenario: SharedCallableScenario,
    result: Option<usize>,
}

impl Callbacks for SharedCallableCallbacks {
    fn after_analysis(&mut self, _compiler: &interface::Compiler, tcx: TyCtxt<'_>) -> Compilation {
        self.result = Some(match self.scenario {
            SharedCallableScenario::FunctionPointerReuse => {
                let mut index = ReachabilityIndex::new(tcx);
                let hooks = NoopReachabilityHooks;
                index.query(
                    ReachabilityRoot::LocalBody(find_local_body(tcx, "expose_fn_target")),
                    &hooks,
                    call_site_options(),
                );
                let snapshot = index.query(
                    ReachabilityRoot::LocalBody(find_local_body(tcx, "call_fn_target")),
                    &hooks,
                    call_site_options(),
                );
                index
                    .graph()
                    .view(&snapshot)
                    .edges()
                    .filter(|edge| edge.kind() == ReachabilityEdgeKind::FnPointerCallTarget)
                    .count()
            }
            SharedCallableScenario::DynDispatchReuse => {
                let mut index = ReachabilityIndex::new(tcx);
                let hooks = NoopReachabilityHooks;
                index.query(
                    ReachabilityRoot::LocalBody(find_local_body(tcx, "expose_dyn_target")),
                    &hooks,
                    call_site_options(),
                );
                let snapshot = index.query(
                    ReachabilityRoot::LocalBody(find_local_body(tcx, "call_dyn_target")),
                    &hooks,
                    call_site_options(),
                );
                index
                    .graph()
                    .view(&snapshot)
                    .edges()
                    .filter(|edge| edge.kind() == ReachabilityEdgeKind::DynDispatchVTableEntry)
                    .count()
            }
            SharedCallableScenario::MultiRootCallableDiscovery => {
                let mut index = ReachabilityIndex::new(tcx);
                let hooks = NoopReachabilityHooks;
                let snapshot = index
                    .query_many(
                        [
                            ReachabilityRoot::LocalBody(find_local_body(tcx, "call_fn_target")),
                            ReachabilityRoot::LocalBody(find_local_body(tcx, "call_dyn_target")),
                            ReachabilityRoot::LocalBody(find_local_body(tcx, "expose_fn_target")),
                            ReachabilityRoot::LocalBody(find_local_body(tcx, "expose_dyn_target")),
                        ],
                        &hooks,
                        call_site_options(),
                    )
                    .expect("the batch has roots");
                let view = index.graph().view(&snapshot);
                let root_count = view.roots().count();
                let target_count = view
                    .edges()
                    .filter(|edge| {
                        matches!(
                            edge.kind(),
                            ReachabilityEdgeKind::FnPointerCallTarget
                                | ReachabilityEdgeKind::DynDispatchVTableEntry
                        )
                    })
                    .count();
                assert_eq!(root_count, 4);
                assert_eq!(target_count, 2);
                root_count
            }
        });
        Compilation::Stop
    }
}

fn call_site_options() -> ReachabilityOptions {
    ReachabilityOptions {
        node_limit: Some(96),
        dyn_dispatch_vtable_edges: DynDispatchVTableEdges::CallSites,
        fn_pointer_edges: FnPointerEdges::CallSites,
        ..ReachabilityOptions::default()
    }
}

fn run_test_compiler(project: &TempProject, callbacks: &mut (dyn Callbacks + Send)) {
    let args = vec![
        String::from("rustc"),
        String::from("--crate-name"),
        String::from("demo"),
        String::from("--crate-type"),
        String::from("lib"),
        String::from("--edition"),
        String::from("2024"),
        String::from("--sysroot"),
        rustc_sysroot(),
        String::from("-Awarnings"),
        project.source.display().to_string(),
    ];
    rustc_driver::run_compiler(&args, callbacks);
}

fn find_local_body(tcx: TyCtxt<'_>, suffix: &str) -> LocalDefId {
    tcx.hir_body_owners()
        .find(|local| tcx.def_path_str(local.to_def_id()).ends_with(suffix))
        .unwrap_or_else(|| panic!("could not find local body ending with `{suffix}`"))
}

fn render_graph<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    result: &ReachabilitySnapshot,
) -> String {
    let view = graph.view(result);
    let mut lines = vec![format!("root {}", render_node(tcx, view.root().kind()))];

    for node in view.nodes() {
        lines.push(format!(
            "node depth={} {}",
            node.depth(),
            render_node(tcx, node.kind())
        ));
    }

    for edge in view.edges() {
        lines.push(format!(
            "edge {} --{:?} -> {}",
            render_node(tcx, edge.source().kind()),
            edge.kind(),
            render_node(tcx, edge.target().kind())
        ));
    }

    lines.sort();
    lines.join("\n")
}

fn render_node<'tcx>(tcx: TyCtxt<'tcx>, node: &ReachabilityNodeKind<'tcx>) -> String {
    match node {
        ReachabilityNodeKind::Instance(instance) => render_instance(tcx, *instance),
        ReachabilityNodeKind::CompilerAssert { message, .. } => format!("assert {message:?}"),
        ReachabilityNodeKind::MacroExpansion { def_id } => {
            format!("macro {}", tcx.def_path_str(*def_id))
        }
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
