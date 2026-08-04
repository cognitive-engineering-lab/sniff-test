mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

use common::{
    CommandOutput, clean_cargo_package_env, copy_dir_all, lock_nested_cargo, repo_root,
    rustc_sysroot,
};

#[derive(Clone, Copy, Debug)]
struct Case {
    behavior: &'static str,
    driver: Driver,
    crate_dir: &'static str,
    args: &'static [&'static str],
    exit_code: i32,
    crate_type: &'static str,
    edition: &'static str,
    source: &'static str,
    manifest: Option<&'static str>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Driver {
    Cargo,
    Direct,
}

impl Case {
    #[must_use]
    const fn cargo(behavior: &'static str) -> Self {
        Self {
            behavior,
            driver: Driver::Cargo,
            crate_dir: "",
            args: &[],
            exit_code: 0,
            crate_type: "lib",
            edition: "2024",
            source: "src/lib.rs",
            manifest: None,
        }
    }

    #[must_use]
    const fn direct(behavior: &'static str) -> Self {
        Self {
            driver: Driver::Direct,
            ..Self::cargo(behavior)
        }
    }

    #[must_use]
    const fn crate_dir(mut self, crate_dir: &'static str) -> Self {
        self.crate_dir = crate_dir;
        self
    }

    #[must_use]
    const fn args(mut self, args: &'static [&'static str]) -> Self {
        self.args = args;
        self
    }

    #[must_use]
    const fn exit_code(mut self, exit_code: i32) -> Self {
        self.exit_code = exit_code;
        self
    }

    #[must_use]
    const fn manifest(mut self, manifest: &'static str) -> Self {
        self.manifest = Some(manifest);
        self
    }
}

struct Binaries {
    cargo: PathBuf,
    driver: PathBuf,
}

macro_rules! fixture_cases {
    ($($fixture:literal => { $($case:ident => $spec:expr;)+ })+) => {
        $(
            $(
                #[test]
                fn $case() {
                    run_named_case(stringify!($case), $fixture, $spec);
                }
            )+
        )+
    };
}

fixture_cases! {
    "executable_artifact" => {
        executable_artifact =>
            Case::cargo("workspace executables without a rustc crate hash");
    }
    "panic_axioms" => {
        panic_axioms => Case::cargo("raw panic paths").exit_code(101);
        driver_panic_axioms => Case::direct("raw panic paths");
    }
    "generic_roots" => {
        generic_roots => Case::cargo("generic roots").exit_code(101);
        driver_generic_roots => Case::direct("generic roots");
    }
    "direct_panic" => {
        direct_panic => Case::cargo("direct panic").exit_code(101);
        driver_direct_panic => Case::direct("direct panic");
    }
    "async_runtime_bodies" => {
        async_runtime_bodies => Case::cargo("async runtime bodies").exit_code(101);
        driver_async_runtime_bodies => Case::direct("async runtime bodies");
    }
    "desugared_runtime_bodies" => {
        desugared_runtime_bodies =>
            Case::cargo("question-mark and derived Debug runtime bodies");
    }
    "target_feature_call_safety" => {
        target_feature_call_safety =>
            Case::cargo("target-feature call safety is relative to the caller")
                .exit_code(101);
    }
    "closure_call_graph" => {
        closure_call_graph => Case::cargo("call graph edges").exit_code(101);
        closure_call_graph_call_sites => Case::cargo("call graph edges with callable call-site attribution")
            .args(&["--manifest", "call-sites.toml"])
            .exit_code(101);
        driver_closure_call_graph => Case::direct("call graph edges");
        driver_closure_call_graph_call_sites =>
            Case::direct("call graph edges with callable call-site attribution")
                .manifest("call-sites.toml");
    }
    "custom_index_impl" => {
        custom_index_impl => Case::cargo("custom index dispatch").exit_code(101);
        driver_custom_index_impl => Case::direct("custom index dispatch");
    }
    "trait_default_method" => {
        trait_default_method => Case::cargo("trait default dispatch").exit_code(101);
        driver_trait_default_method => Case::direct("trait default dispatch");
    }
    "dyn_dispatch_call_site" => {
        dyn_dispatch_call_site => Case::cargo("dyn dispatch call-site attribution").exit_code(101);
        driver_dyn_dispatch_call_site => Case::direct("dyn dispatch call-site attribution");
    }
    "dyn_dispatch_same_trait" => {
        dyn_dispatch_same_trait => Case::cargo("dyn dispatch same-trait approximation").exit_code(101);
        driver_dyn_dispatch_same_trait => Case::direct("dyn dispatch same-trait approximation");
    }
    "supertrait_dyn_dispatch" => {
        supertrait_dyn_dispatch => Case::cargo("supertrait methods match dyn vtable entries")
            .exit_code(101);
        driver_supertrait_dyn_dispatch =>
            Case::direct("supertrait methods match dyn vtable entries");
    }
    "documented_obligation" => {
        documented_obligation => Case::cargo("documented panic obligation").exit_code(101);
        documented_obligation_allowed => Case::cargo("allowed documented panic obligation")
            .args(&["--manifest", "allow.toml"]);
        driver_documented_obligation => Case::direct("documented panic obligation");
        driver_documented_obligation_allowed => Case::direct("allowed documented panic obligation")
            .manifest("allow.toml");
    }
    "contract_overrides" => {
        contract_overrides => Case::cargo("documentation overrides");
        driver_contract_overrides => Case::direct("documentation overrides");
    }
    "converging_effect_paths" => {
        converging_effect_paths =>
            Case::cargo("raw effect paths survive convergence").exit_code(101);
    }
    "release_pruning" => {
        release_pruning => Case::cargo("release profile pruning").exit_code(101);
    }
    "optimizer_pruning" => {
        optimizer_pruning => Case::cargo("optimizer pruning");
    }
    "feature_gated" => {
        feature_gated => Case::cargo("feature-enabled raw panic")
            .args(&["--", "--features", "dangerous"])
            .exit_code(101);
        feature_gated_default => Case::cargo("feature-default clean");
    }
    "suppression" => {
        suppression => Case::cargo("suppressed");
        suppression_miss => Case::cargo("suppression miss")
            .args(&["--manifest", "miss.toml"])
            .exit_code(101);
        driver_suppression => Case::direct("suppressed");
        driver_suppression_miss => Case::direct("suppression miss").manifest("miss.toml");
    }
    "dependency_obligation" => {
        dependency_obligation => Case::cargo("dependency obligation").crate_dir("app");
        dependency_obligation_relative_cache => Case::cargo("relative dependency cache")
            .crate_dir("app")
            .args(&["--cache-dir", ".sniff-cache"]);
    }
    "dependency_safety" => {
        dependency_safety => Case::cargo("dependency safety effect")
            .crate_dir("app")
            .exit_code(101);
    }
    "dependency_async_panic" => {
        dependency_async_panic => Case::cargo("cached dependency async runtime body")
            .crate_dir("app")
            .exit_code(101);
    }
    "dependency_unsafe_trait_call" => {
        dependency_unsafe_trait_call =>
            Case::cargo("cached generic unsafe trait-call justification")
                .crate_dir("app");
    }
    "dependency_safety_contract" => {
        dependency_safety_contract => Case::cargo("cached safety markers and concrete findings")
            .crate_dir("app")
            .exit_code(101);
        dependency_safety_policy => Case::cargo("cached safety finding policy")
            .crate_dir("app")
            .args(&["--manifest", "policy.toml"])
            .exit_code(101);
        dependency_safety_unnamed_marker => Case::cargo("cached named safety requirement")
            .crate_dir("app")
            .args(&["--manifest", "unnamed-marker.toml"])
            .exit_code(101);
        dependency_safety_ambiguous_marker => Case::cargo("ambiguous cached safety marker")
            .crate_dir("app")
            .args(&["--manifest", "ambiguous-marker.toml"])
            .exit_code(101);
    }
    "dependency_safety_partial_requirements" => {
        dependency_safety_partial_requirements =>
            Case::cargo("cached safety markers satisfy only named requirements they claim")
                .crate_dir("app")
                .exit_code(101);
    }
    "partial_effect_requirements" => {
        partial_effect_requirements => Case::cargo("partial cached requirement propagation")
            .crate_dir("app")
            .exit_code(101);
    }
    "dependency_safety_incomplete" => {
        dependency_safety_incomplete => Case::cargo("incomplete safety cache propagation")
            .crate_dir("app")
            .exit_code(101);
    }
    "dependency_identity" => {
        dependency_identity => Case::cargo("dependency cache identity across sessions")
            .crate_dir("app")
            .exit_code(101);
    }
    "dependency_transitive_panic" => {
        dependency_transitive_panic => Case::cargo("panic evidence crosses two cache boundaries")
            .crate_dir("app")
            .exit_code(101);
        dependency_transitive_panic_four_crates =>
            Case::cargo("panic traces survive three cache boundaries")
                .crate_dir("outer")
                .exit_code(101);
    }
    "dependency_panic_incomplete_boundary" => {
        dependency_panic_incomplete_boundary =>
            Case::cargo("incomplete panic cache stops at documented boundaries")
                .crate_dir("app");
    }
    "dependency_panic_incomplete_resolved" => {
        dependency_panic_incomplete_resolved =>
            Case::cargo("resolved cached panics do not hide incomplete dependency analysis")
                .crate_dir("app")
                .exit_code(101);
    }
    "dependency_mixed_panic" => {
        dependency_mixed_panic => Case::cargo("cached raw and trusted panic evidence coexist")
            .crate_dir("app")
            .exit_code(101);
    }
    "dependency_cross_origin_ambiguity" => {
        dependency_cross_origin_marker_is_ambiguous =>
            Case::cargo("one marker cannot justify local and cached dependency effects")
                .crate_dir("app")
                .exit_code(101);
    }
    "dependency_panic_contract" => {
        dependency_panic_contract => Case::cargo("cached panic marker contracts")
            .crate_dir("app")
            .exit_code(101);
    }
    "std_trait_impl_glob" => {
        std_trait_impl_glob => Case::cargo("trait-impl methods match trusted globs");
        driver_std_trait_impl_glob => Case::direct("trait-impl methods match trusted globs");
    }
    "unsafe_ops" => {
        unsafe_ops => Case::cargo("non-call unsafe operations need justification");
        driver_unsafe_ops => Case::direct("non-call unsafe operations need justification");
    }
    "unsafe_closure_inherit" => {
        unsafe_closure_inherit => Case::cargo("closures inherit unsafe block justifications");
        driver_unsafe_closure_inherit =>
            Case::direct("closures inherit unsafe block justifications");
    }
    "unsafe_const_init" => {
        unsafe_const_init => Case::cargo("const and static initializers are skipped");
        driver_unsafe_const_init => Case::direct("const and static initializers are skipped");
    }
    "node_limit" => {
        node_limit => Case::cargo("halted traversals fail loudly").exit_code(101);
        driver_node_limit => Case::direct("halted traversals fail loudly");
    }
    "safety_node_limit" => {
        safety_node_limit => Case::cargo("safety traversal truncation fails loudly").exit_code(101);
    }
    "indirect_calls" => {
        indirect_calls => Case::cargo("indirect calls surface obligations or boundaries");
        driver_indirect_calls =>
            Case::direct("indirect calls surface obligations or boundaries");
    }
    "chain_markers" => {
        chain_markers => Case::cargo("markers anchor to chain links");
        driver_chain_markers => Case::direct("markers anchor to chain links");
    }
    "visibility_roots" => {
        visibility_roots => Case::cargo("effective visibility selects roots").exit_code(101);
        visibility_roots_panic_ignored => Case::cargo("panic ignores do not suppress safety")
            .args(&["--manifest", "panic-ignore.toml"]);
        driver_visibility_roots => Case::direct("effective visibility selects roots");
    }
    "vendored_dep" => {
        vendored_dep => Case::cargo("vendored path deps are not workspace code");
    }
    "safe_markers" => {
        safe_markers => Case::cargo("panic marker satisfaction").exit_code(101);
        driver_safe_markers => Case::direct("panic marker satisfaction");
    }
    "transitive_effect_markers" => {
        transitive_effect_markers => Case::cargo("transitive panic and safety markers")
            .exit_code(101);
    }
    "panic_requirements" => {
        panic_requirements => Case::cargo("panic requirement satisfaction");
        driver_panic_requirements => Case::direct("panic requirement satisfaction");
    }
    "ambiguous_markers" => {
        ambiguous_markers => Case::cargo("ambiguous marker allow policy");
        ambiguous_markers_warn => Case::cargo("ambiguous marker warn policy")
            .args(&["--manifest", "warn.toml"]);
        ambiguous_markers_strict => Case::cargo("ambiguous marker default error policy")
            .args(&["--manifest", "strict.toml"])
            .exit_code(101);
        driver_ambiguous_markers => Case::direct("ambiguous marker allow policy");
        driver_ambiguous_markers_warn => Case::direct("ambiguous marker warn policy")
            .manifest("warn.toml");
        driver_ambiguous_markers_strict => Case::direct("ambiguous marker default error policy")
            .manifest("strict.toml");
    }
    "ambiguous_safety" => {
        ambiguous_safety_allow => Case::cargo("ambiguous safety allow policy")
            .args(&["--manifest", "allow.toml"]);
        ambiguous_safety_warn => Case::cargo("ambiguous safety warn policy")
            .args(&["--manifest", "warn.toml"]);
        ambiguous_safety_strict => Case::cargo("ambiguous safety default error policy")
            .exit_code(101);
        ambiguous_safety_macro_instances =>
            Case::cargo("definition-site safety markers are scoped to macro instances")
                .args(&["--manifest", "macro-instances.toml"]);
        ambiguous_safety_macro_shared =>
            Case::cargo("shared safety markers remain ambiguous within one occurrence")
                .args(&["--manifest", "macro-shared.toml"])
                .exit_code(101);
        driver_ambiguous_safety_strict => Case::direct("ambiguous safety default error policy");
    }
    "safety_requirements" => {
        safety_requirements => Case::cargo("safety requirement satisfaction");
        safety_requirements_call_sites => Case::cargo("safety callable call-site attribution")
            .args(&["--manifest", "call-sites.toml"]);
        safety_requirements_allowed => Case::cargo("allowed safety findings")
            .args(&["--manifest", "allow.toml"]);
        safety_requirements_denied => Case::cargo("denied safety finding")
            .args(&["--manifest", "deny.toml"])
            .exit_code(101);
        safety_requirements_ignored => Case::cargo("ignored safety namespaces")
            .args(&["--manifest", "ignore.toml"]);
        safety_requirements_obligations => Case::cargo("configured safety obligations")
            .args(&["--manifest", "obligations.toml"]);
        driver_safety_requirements => Case::direct("safety requirement satisfaction");
    }
    "local_generic_impl_contract" => {
        local_generic_impl_contract =>
            Case::cargo("statically selected generic impl contract");
    }
    "safety_callable_sites" => {
        safety_callable_sites => Case::cargo("independent callable call sites");
    }
    "marker_placement" => {
        marker_placement => Case::cargo("marker placement").exit_code(101);
        driver_marker_placement => Case::direct("marker placement");
    }
    "macro_expansion" => {
        macro_expansion => Case::cargo("macro expansion trace").exit_code(101);
        macro_expansion_source_callsite => Case::cargo("source-callsite marker probing")
            .args(&["--manifest", "source-callsite.toml"])
            .exit_code(101);
        macro_expansion_static_assert_ignored => Case::cargo("ignored macro expansion")
            .args(&["--manifest", "ignore-static.toml"])
            .exit_code(101);
        driver_macro_expansion => Case::direct("macro expansion trace");
        driver_macro_expansion_source_callsite => Case::direct("source-callsite marker probing")
            .manifest("source-callsite.toml");
        driver_macro_expansion_static_assert_ignored => Case::direct("ignored macro expansion")
            .manifest("ignore-static.toml");
    }
    "trusted_boundaries" => {
        trusted_boundaries => Case::cargo("trusted boundary");
        trusted_boundaries_call_sites => Case::cargo("trusted boundary call-site attribution")
            .args(&["--manifest", "call-sites.toml"]);
        trusted_boundaries_untrusted => Case::cargo("untrusted boundary")
            .args(&["--manifest", "untrusted.toml"])
            .exit_code(101);
        driver_trusted_boundaries => Case::direct("trusted boundary");
        driver_trusted_boundaries_untrusted => Case::direct("untrusted boundary")
            .manifest("untrusted.toml");
    }
    "report_roots" => {
        report_roots_public => Case::cargo("public report roots").exit_code(101);
        report_roots_all => Case::cargo("all report roots")
            .args(&["--manifest", "all.toml"])
            .exit_code(101);
        report_roots_explicit => Case::cargo("explicit report roots")
            .args(&["--manifest", "explicit.toml"])
            .exit_code(101);
        driver_report_roots_public => Case::direct("public report roots");
        driver_report_roots_all => Case::direct("all report roots").manifest("all.toml");
        driver_report_roots_explicit => Case::direct("explicit report roots").manifest("explicit.toml");
    }
    "direct_driver_panic" => {
        direct_driver_panic => Case::direct("direct driver raw panic");
    }
    "direct_driver_safe" => {
        direct_driver_safe => Case::direct("direct driver clean");
    }
}

#[test]
fn trusted_boundaries_keep_unknown_callable_effects() {
    let repo = repo_root();
    let binaries = Binaries::from_cargo();
    let sysroot = rustc_sysroot();
    let case = Case::cargo("unknown callable alternatives remain generic");
    let messages = run_case(
        &repo,
        &binaries,
        &sysroot,
        "trusted_boundaries_keep_unknown_callable_effects",
        "trusted_boundaries",
        &case,
    );
    let findings = messages
        .iter()
        .find(|message| message["artifact"]["crate-name"] == "trusted_boundaries")
        .and_then(|message| message["findings"].as_array())
        .expect("trusted boundary fixture findings");
    let has_finding = |root, kind| {
        findings
            .iter()
            .any(|finding| finding["root"] == root && finding["kind"] == kind)
    };

    assert!(
        has_finding(
            "trusted_boundaries::trusted_through_fn_pointer",
            "indirect-call-boundary"
        ),
        "an unknown safe function-pointer alternative must remain a panic boundary: {findings:?}"
    );
    assert!(
        has_finding(
            "trusted_boundaries::trusted_unsafe_through_fn_pointer",
            "unsafe-call-missing-justification"
        ),
        "an unknown unsafe function-pointer alternative must retain its safety effect: {findings:?}"
    );
}

#[test]
fn callable_marker_is_not_ambiguous_between_generic_and_concrete_evidence() {
    let repo = repo_root();
    let binaries = Binaries::from_cargo();
    let sysroot = rustc_sysroot();
    let case = Case::cargo("one callable site has one semantic panic group")
        .args(&["--manifest", "call-sites.toml"])
        .exit_code(101);
    let messages = run_case(
        &repo,
        &binaries,
        &sysroot,
        "callable_marker_is_not_ambiguous_between_generic_and_concrete_evidence",
        "closure_call_graph",
        &case,
    );
    let findings = messages
        .iter()
        .find(|message| message["artifact"]["crate-name"] == "closure_call_graph")
        .and_then(|message| message["findings"].as_array())
        .expect("closure call graph findings");

    let marked_findings = findings
        .iter()
        .filter(|finding| finding["root"] == "closure_call_graph::marked_fn_pointer_call")
        .collect::<Vec<_>>();
    assert!(
        marked_findings.is_empty(),
        "each call marker must cover that call's generic and concrete evidence: {marked_findings:?}"
    );
}

#[test]
fn local_foreign_function_does_not_query_extern_crate_paths() {
    let repo = repo_root();
    let binaries = Binaries::from_cargo();
    let sysroot = rustc_sysroot();
    let case = Case::cargo("local foreign functions are not extern crates");
    let messages = run_case(
        &repo,
        &binaries,
        &sysroot,
        "local_foreign_function_does_not_query_extern_crate_paths",
        "local_foreign_function",
        &case,
    );
    let report = messages
        .iter()
        .find(|message| message["artifact"]["crate-name"] == "local_foreign_function")
        .expect("fixture should emit its local artifact report");
    assert!(
        messages
            .iter()
            .all(|message| message.get("scope").is_none()),
        "workspace-only reports must not serialize the removed scope field: {messages:?}"
    );
    let findings = report["findings"]
        .as_array()
        .expect("local foreign function findings");
    assert!(
        findings.is_empty(),
        "a justified local foreign call should be clean: {findings:?}"
    );
}

fn run_named_case(name: &'static str, fixture_name: &'static str, case: Case) {
    let repo = repo_root();
    let binaries = Binaries::from_cargo();
    let sysroot = rustc_sysroot();
    let messages = run_case(&repo, &binaries, &sysroot, name, fixture_name, &case);
    insta::assert_json_snapshot!(name, messages);
}

#[test]
fn unselected_callable_evidence_does_not_refine_selected_call_sites() {
    let name = "unselected_callable_evidence_does_not_refine_selected_call_sites";
    let repo = repo_root();
    let binaries = Binaries::from_cargo();
    let sysroot = rustc_sysroot();
    let messages = run_case(
        &repo,
        &binaries,
        &sysroot,
        name,
        "callable_root_isolation",
        &Case::cargo("call-site attribution stays within selected-root reachability"),
    );
    let report = messages
        .iter()
        .find(|message| message["artifact"]["crate-name"] == "callable_root_isolation")
        .expect("fixture should emit one workspace report");

    assert_eq!(
        report["findings"],
        serde_json::json!([]),
        "unused callable evidence must not attach panicking targets to selected roots"
    );
}

#[test]
fn dependency_units_are_silent_while_workspace_reinterprets_their_safety_ir() {
    let repo = repo_root();
    let binaries = Binaries::from_cargo();
    let sysroot = rustc_sysroot();
    let case = Case::cargo("dependency safety findings match panic scope behavior")
        .crate_dir("app")
        .exit_code(101);
    let messages = run_case(
        &repo,
        &binaries,
        &sysroot,
        "dependency_units_are_silent_while_workspace_reinterprets_their_safety_ir",
        "dependency_safety",
        &case,
    );
    assert_eq!(
        messages.len(),
        1,
        "the Cargo run must emit exactly one workspace report: {messages:?}"
    );
    assert!(
        messages
            .iter()
            .all(|message| message["artifact"]["crate-name"] != "dependency_safety"),
        "dependency rustc units must not emit public JSON reports: {messages:?}"
    );
    let workspace = messages
        .iter()
        .find(|message| message["artifact"]["crate-name"] == "dependency_safety_app")
        .expect("fixture should emit one workspace artifact report");
    assert!(
        workspace["findings"]
            .as_array()
            .is_some_and(|findings| !findings.is_empty()),
        "the workspace must reinterpret reachable dependency safety IR"
    );
}

#[test]
fn dependency_safety_ir_findings_keep_their_effect_spans() {
    let repo = repo_root();
    let binaries = Binaries::from_cargo();
    let sysroot = rustc_sysroot();
    let case = Case::cargo("cached safety findings retain their originating spans")
        .crate_dir("app")
        .exit_code(101);
    let messages = run_case(
        &repo,
        &binaries,
        &sysroot,
        "dependency_safety_ir_findings_keep_their_effect_spans",
        "dependency_safety_contract",
        &case,
    );
    let report = messages
        .iter()
        .find(|message| message["artifact"]["crate-name"] == "dependency_safety_contract_app")
        .expect("fixture should emit the application report");
    let effect_spans = report["findings"]
        .as_array()
        .expect("report findings should be an array")
        .iter()
        .filter(|finding| finding["root"] == "dependency_safety_contract_app::reaches_two_effects")
        .map(|finding| {
            finding["span"]
                .as_str()
                .expect("dependency IR finding should retain its verified effect span")
        })
        .collect::<Vec<_>>();

    assert_eq!(
        effect_spans,
        [
            "[FIXTURE]/dep/src/lib.rs:2:26: 2:34",
            "[FIXTURE]/dep/src/lib.rs:3:27: 3:35",
        ]
    );
}

#[test]
fn dependency_ir_retains_private_helper_trace() {
    let repo = repo_root();
    let binaries = Binaries::from_cargo();
    let sysroot = rustc_sysroot();
    let case = Case::cargo("dependency IR retains evidence through private helpers")
        .crate_dir("app")
        .exit_code(101);
    let messages = run_case(
        &repo,
        &binaries,
        &sysroot,
        "dependency_ir_retains_private_helper_trace",
        "dependency_generic_private_panic",
        &case,
    );
    let report = messages
        .iter()
        .find(|message| message["artifact"]["crate-name"] == "dependency_generic_private_panic_app")
        .expect("fixture should emit the application report");
    let findings = report["findings"].as_array().expect("application findings");
    assert!(
        !findings
            .iter()
            .any(|finding| finding["kind"] == "panic-analysis-incomplete"),
        "the exact dependency graph should completely interpret the reachable path: {findings:?}"
    );
    let finding = findings
        .iter()
        .find(|finding| {
            finding["root"] == "dependency_generic_private_panic_app::caller"
                && finding["kind"] == "panic-invocation"
        })
        .expect("the workspace should derive the panic from the dependency IR");
    let trace = finding["trace"]
        .as_array()
        .expect("dependency panic should include a trace");

    assert!(
        trace.iter().any(|step| {
            step.as_str()
                .is_some_and(|step| step.contains("dependency_generic_private_panic::hidden"))
        }),
        "trace should cross the dependency's private helper: {trace:?}"
    );
}

#[test]
fn consumer_overlay_resolves_generic_dependency_dispatch_to_workspace_impl() {
    let repo = repo_root();
    let binaries = Binaries::from_cargo();
    let sysroot = rustc_sysroot();
    let case = Case::cargo("consumer IR retains exact cross-crate generic dispatch")
        .crate_dir("app")
        .exit_code(101);
    let messages = run_case(
        &repo,
        &binaries,
        &sysroot,
        "consumer_overlay_resolves_generic_dependency_dispatch_to_workspace_impl",
        "dependency_generic_local_impl",
        &case,
    );
    let report = messages
        .iter()
        .find(|message| message["artifact"]["crate-name"] == "dependency_generic_local_impl_app")
        .expect("fixture should emit the application report");
    let findings = report["findings"].as_array().expect("application findings");
    assert!(
        !findings
            .iter()
            .any(|finding| finding["kind"] == "panic-analysis-incomplete"),
        "the consumer overlay should completely interpret the exact dependency instance: \
         {findings:?}"
    );
    assert!(
        !findings
            .iter()
            .any(|finding| finding["kind"] == "ambiguous-safety-marker"),
        "one definition-site unsafe scope must remain one effect group in its consumer overlay: \
         {findings:?}"
    );

    for kind in ["panic-invocation", "unsafe-op-missing-justification"] {
        let finding = findings
            .iter()
            .find(|finding| {
                finding["root"] == "dependency_generic_local_impl_app::caller"
                    && finding["kind"] == kind
            })
            .unwrap_or_else(|| {
                panic!("the workspace-local trait implementation should expose `{kind}`")
            });
        let trace = finding["trace"]
            .as_array()
            .expect("cross-artifact finding should include a trace");
        assert!(
            trace.iter().any(|step| {
                step.as_str()
                    .is_some_and(|step| step.contains("dependency_generic_local_impl::invoke"))
            }) && trace.iter().any(|step| {
                step.as_str()
                    .is_some_and(|step| step.contains("Action>::apply"))
            }),
            "trace should cross the exact dependency instance into the local impl: {trace:?}"
        );
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the regression test compiles both complete-IR and missing-IR variants"
)]
fn expanded_generic_dependency_resumes_at_private_helper() {
    let name = "expanded_generic_dependency_resumes_at_private_helper";
    let fixture_name = "dependency_generic_private_panic";
    let repo = repo_root();
    let binaries = Binaries::from_cargo();
    let sysroot = rustc_sysroot();
    let fixture = repo.join("tests/fixtures").join(fixture_name);
    let temp = tempfile::Builder::new()
        .prefix(&format!("sniff-test-{name}-"))
        .tempdir()
        .expect("temporary fixture directory");
    let root = temp.path().join(fixture_name);
    copy_dir_all(&fixture, &root).expect("copy fixture");
    let cache_dir = temp.path().join("cache");
    let out_dir = temp.path().join("out");
    fs::create_dir_all(&out_dir).expect("create rustc output directory");
    let manifest = root.join("app/sniff-test.toml");

    let mut dependency = Command::new(&binaries.driver);
    clean_cargo_package_env(&mut dependency);
    let dependency = dependency
        .arg("--dependency")
        .args(["--manifest"])
        .arg(&manifest)
        .args(["--cache-dir"])
        .arg(&cache_dir)
        .args(["--message-format", "json", "--color", "never", "--"])
        .args([
            "--crate-name",
            "dependency_generic_private_panic",
            "--crate-type",
            "rlib",
            "--edition",
            "2024",
        ])
        .arg(root.join("dep/src/lib.rs"))
        .args(["--sysroot", sysroot.trim(), "--out-dir"])
        .arg(&out_dir)
        .args(["-C", "extra-filename=-audit"])
        .current_dir(&root)
        .output()
        .unwrap_or_else(|error| panic!("{name}: failed to compile dependency: {error}"));
    let dependency = CommandOutput::from_output(dependency);
    assert!(
        dependency.status.success(),
        "{name}: dependency compilation failed\nstdout:\n{}\nstderr:\n{}",
        dependency.stdout,
        dependency.stderr
    );

    let dependency_rlib = out_dir.join("libdependency_generic_private_panic-audit.rlib");
    assert!(
        dependency_rlib.exists(),
        "{name}: missing dependency artifact {}",
        dependency_rlib.display()
    );

    let compile_application = |cache_dir: &Path, suffix: &str| {
        let mut application = Command::new(&binaries.driver);
        clean_cargo_package_env(&mut application);
        let output = application
            .args(["--manifest"])
            .arg(&manifest)
            .args(["--cache-dir"])
            .arg(cache_dir)
            .args(["--message-format", "json", "--color", "never", "--"])
            .args([
                "--crate-name",
                "dependency_generic_private_panic_app",
                "--crate-type",
                "lib",
                "--edition",
                "2024",
            ])
            .arg(root.join("app/src/lib.rs"))
            .args(["--sysroot", sysroot.trim(), "--out-dir"])
            .arg(&out_dir)
            .args(["-C", &format!("extra-filename={suffix}"), "--extern"])
            .arg(format!(
                "dependency_generic_private_panic={}",
                dependency_rlib.display()
            ))
            .arg("-Zno-codegen")
            .env("CARGO_PRIMARY_PACKAGE", "1")
            .current_dir(&root)
            .output()
            .unwrap_or_else(|error| panic!("{name}: failed to compile application: {error}"));
        CommandOutput::from_output(output)
    };
    let application = compile_application(&cache_dir, "-app-audit");
    assert!(
        application.status.success(),
        "{name}: application compilation failed\nstdout:\n{}\nstderr:\n{}",
        application.stdout,
        application.stderr
    );

    let case = Case::direct("expanded dependency MIR resumes from exact private IR");
    let messages = parse_messages(&application, &root, &sysroot, name, fixture_name, &case);
    let report = messages
        .iter()
        .find(|message| message["artifact"]["crate-name"] == "dependency_generic_private_panic_app")
        .expect("application report");
    let findings = report["findings"].as_array().expect("application findings");
    assert!(
        !findings
            .iter()
            .any(|finding| finding["kind"] == "panic-analysis-incomplete"),
        "exact private resume should complete dependency analysis: {findings:?}"
    );
    let finding = findings
        .iter()
        .find(|finding| finding["kind"] == "panic-invocation")
        .expect("private-helper panic derived from dependency IR");
    assert_eq!(finding["target"], "core::std::rt::panic_fmt");
    let trace = finding["trace"].as_array().expect("dependency panic trace");
    assert!(
        trace.iter().any(|step| {
            step.as_str()
                .is_some_and(|step| step.contains("dependency_generic_private_panic::api"))
        }) && trace.iter().any(|step| {
            step.as_str()
                .is_some_and(|step| step.contains("dependency_generic_private_panic::hidden"))
        }),
        "trace should enter the generic API and resume at its private helper: {trace:?}"
    );

    let mut pathless_application = Command::new(&binaries.driver);
    clean_cargo_package_env(&mut pathless_application);
    let pathless_application = pathless_application
        .args(["--manifest"])
        .arg(&manifest)
        .args(["--cache-dir"])
        .arg(&cache_dir)
        .args(["--message-format", "json", "--color", "never", "--"])
        .args([
            "--crate-name",
            "dependency_generic_private_panic_app",
            "--crate-type",
            "lib",
            "--edition",
            "2024",
        ])
        .arg(root.join("app/src/lib.rs"))
        .args(["--sysroot", sysroot.trim(), "--out-dir"])
        .arg(&out_dir)
        .args(["-C", "extra-filename=-app-pathless", "-L"])
        .arg(&out_dir)
        .args([
            "--extern",
            "dependency_generic_private_panic",
            "-Zno-codegen",
        ])
        .env("CARGO_PRIMARY_PACKAGE", "1")
        .current_dir(&root)
        .output()
        .unwrap_or_else(|error| panic!("{name}: failed to compile pathless application: {error}"));
    let pathless_application = CommandOutput::from_output(pathless_application);
    assert!(
        pathless_application.status.success(),
        "{name}: pathless --extern application compilation failed\nstdout:\n{}\nstderr:\n{}",
        pathless_application.stdout,
        pathless_application.stderr
    );
    assert!(
        pathless_application
            .stdout
            .contains(r#""reason":"sniff-test-artifact""#),
        "{name}: pathless --extern application must emit its workspace report\nstdout:\n{}",
        pathless_application.stdout
    );
    let pathless_messages = parse_messages(
        &pathless_application,
        &root,
        &sysroot,
        name,
        fixture_name,
        &case,
    );
    let pathless_report = pathless_messages
        .iter()
        .find(|message| message["artifact"]["crate-name"] == "dependency_generic_private_panic_app")
        .expect("pathless application report");
    assert!(
        pathless_report["dependencies"]
            .as_array()
            .is_some_and(|dependencies| dependencies.iter().any(|dependency| {
                dependency["extern-name"] == "dependency_generic_private_panic"
            })),
        "{name}: pathless extern must bind the dependency artifact: {pathless_report:?}"
    );
    assert!(
        pathless_report["findings"]
            .as_array()
            .is_some_and(|findings| findings
                .iter()
                .any(|finding| finding["kind"] == "panic-invocation")),
        "{name}: pathless extern must interpret the dependency panic: {pathless_report:?}"
    );

    let missing_cache_application =
        compile_application(&temp.path().join("empty-cache"), "-app-missing-cache");
    assert!(
        !missing_cache_application.status.success(),
        "{name}: missing dependency IR must fail the run\nstdout:\n{}\nstderr:\n{}",
        missing_cache_application.stdout,
        missing_cache_application.stderr
    );
    assert!(
        !missing_cache_application
            .stdout
            .contains(r#""reason":"sniff-test-artifact""#),
        "{name}: a failed workspace run must not emit an analysis report\nstdout:\n{}",
        missing_cache_application.stdout
    );
    let required_ir_error = "error: failed to load required dependency artifact IR";
    assert!(
        missing_cache_application.stderr.contains(required_ir_error),
        "{name}: missing dependency IR should emit a tool error\nstderr:\n{}",
        missing_cache_application.stderr
    );
    assert_eq!(
        missing_cache_application
            .stderr
            .matches(required_ir_error)
            .count(),
        1,
        "{name}: missing dependency IR should fail exactly once\nstderr:\n{}",
        missing_cache_application.stderr
    );
}

#[test]
fn every_cargo_run_reinterprets_and_emits_the_workspace_report() {
    let name = "every_cargo_run_reinterprets_and_emits_the_workspace_report";
    let fixture_name = "panic_requirements";
    let case = Case::cargo("workspace units rerun while dependency IR stays reusable");
    let repo = repo_root();
    let binaries = Binaries::from_cargo();

    let fixture = repo.join("tests/fixtures").join(fixture_name);
    assert!(
        fixture.exists(),
        "{} ({}/{}): missing fixture {}",
        name,
        fixture_name,
        case.behavior,
        fixture.display()
    );
    let temp = tempfile::Builder::new()
        .prefix(&format!("sniff-test-{name}-"))
        .tempdir()
        .unwrap_or_else(|error| panic!("{name}: failed to create temp dir: {error}"));
    let root = temp.path().join(fixture_name);
    copy_dir_all(&fixture, &root)
        .unwrap_or_else(|error| panic!("{name}: failed to copy fixture: {error}"));

    let artifact_filenames = || {
        let deps = root.join("target/sniff-test/release/deps");
        fs::read_dir(&deps)
            .unwrap_or_else(|error| {
                panic!(
                    "{name}: failed to read Cargo artifacts {}: {error}",
                    deps.display()
                )
            })
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .collect::<std::collections::BTreeSet<_>>()
    };
    let (first, first_artifacts, second, second_artifacts) = {
        let _cargo_guard = lock_nested_cargo();
        let first = run_cargo_case(&binaries.cargo, &root, name, &case);
        let first_artifacts = artifact_filenames();
        let second = run_cargo_case(&binaries.cargo, &root, name, &case);
        let second_artifacts = artifact_filenames();
        (first, first_artifacts, second, second_artifacts)
    };
    for output in [&first, &second] {
        assert!(
            output.status.success(),
            "stdout:\n{}\nstderr:\n{}",
            output.stdout,
            output.stderr
        );
    }
    assert!(
        first.stdout.contains(r#""reason":"sniff-test-artifact""#),
        "first stdout:\n{}",
        first.stdout
    );
    assert!(
        second.stdout.contains(r#""reason":"sniff-test-artifact""#),
        "second stdout:\n{}",
        second.stdout
    );
    assert_eq!(
        first_artifacts, second_artifacts,
        "workspace run nonce must not churn Cargo artifact filenames"
    );
}

#[test]
fn cargo_fresh_workspace_run_rejects_a_missing_dependency_ir_cache() {
    let name = "cargo_fresh_workspace_run_rejects_a_missing_dependency_ir_cache";
    let fixture_name = "dependency_safety";
    let case = Case::cargo("fresh workspace validates required dependency IR").crate_dir("app");
    let repo = repo_root();
    let binaries = Binaries::from_cargo();
    let fixture = repo.join("tests/fixtures").join(fixture_name);
    let temp = tempfile::Builder::new()
        .prefix(&format!("sniff-test-{name}-"))
        .tempdir()
        .unwrap_or_else(|error| panic!("{name}: failed to create temp dir: {error}"));
    let root = temp.path().join(fixture_name);
    copy_dir_all(&fixture, &root)
        .unwrap_or_else(|error| panic!("{name}: failed to copy fixture: {error}"));
    fs::write(
        root.join("app/sniff-test.toml"),
        "[safety.lints]\nunsafe-op-missing-justification = \"warn\"\n",
    )
    .unwrap_or_else(|error| panic!("{name}: failed to install warning-only policy: {error}"));

    let first = {
        let _cargo_guard = lock_nested_cargo();
        run_cargo_case(&binaries.cargo, &root, name, &case)
    };
    assert_eq!(
        first.status.code(),
        Some(case.exit_code),
        "first stdout:\n{}\nfirst stderr:\n{}",
        first.stdout,
        first.stderr
    );
    assert!(
        first.stdout.contains(r#""reason":"sniff-test-artifact""#),
        "first stdout:\n{}",
        first.stdout
    );

    let artifact_cache_dir = root.join("app/target/sniff-test/sniff-test-cache/v13/artifacts");
    let dependency_cache = fs::read_dir(&artifact_cache_dir)
        .unwrap_or_else(|error| {
            panic!(
                "{name}: failed to read artifact cache {}: {error}",
                artifact_cache_dir.display()
            )
        })
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            fs::read_to_string(path)
                .ok()
                .and_then(|source| serde_json::from_str::<Value>(&source).ok())
                .is_some_and(|cache| cache["artifact"]["crate-name"] == "dependency_safety")
        })
        .unwrap_or_else(|| {
            panic!(
                "{name}: dependency artifact cache missing from {}",
                artifact_cache_dir.display()
            )
        });
    fs::remove_file(&dependency_cache).unwrap_or_else(|error| {
        panic!(
            "{name}: failed to remove dependency cache {}: {error}",
            dependency_cache.display()
        )
    });

    let second = {
        let _cargo_guard = lock_nested_cargo();
        run_cargo_case(&binaries.cargo, &root, name, &case)
    };
    assert_eq!(
        second.status.code(),
        Some(101),
        "second stdout:\n{}\nsecond stderr:\n{}",
        second.stdout,
        second.stderr
    );
    assert!(
        !second.stdout.contains(r#""reason":"sniff-test-artifact""#),
        "failed workspace run must not emit a report:\n{}",
        second.stdout
    );
    let required_ir_error = "error: failed to load required dependency artifact IR";
    assert_eq!(
        second.stderr.matches(required_ir_error).count(),
        1,
        "fresh workspace run must fail exactly once for missing dependency IR:\n{}",
        second.stderr
    );
}

impl Binaries {
    fn from_cargo() -> Self {
        Self {
            cargo: PathBuf::from(env!("CARGO_BIN_EXE_cargo-sniff-test")),
            driver: PathBuf::from(env!("CARGO_BIN_EXE_sniff-test-driver")),
        }
    }
}

fn run_case(
    repo: &Path,
    binaries: &Binaries,
    sysroot: &str,
    name: &str,
    fixture_name: &str,
    case: &Case,
) -> Vec<Value> {
    let fixture = repo.join("tests/fixtures").join(fixture_name);
    assert!(
        fixture.exists(),
        "{} ({}/{}): missing fixture {}",
        name,
        fixture_name,
        case.behavior,
        fixture.display()
    );

    let temp = tempfile::Builder::new()
        .prefix(&format!("sniff-test-{name}-"))
        .tempdir()
        .unwrap_or_else(|error| panic!("{name}: failed to create temp dir: {error}"));
    let root = temp.path().join(fixture_name);
    copy_dir_all(&fixture, &root)
        .unwrap_or_else(|error| panic!("{name}: failed to copy fixture: {error}"));

    let output = match case.driver {
        Driver::Direct => {
            run_direct_driver_case(&binaries.driver, sysroot, &root, name, fixture_name, case)
        }
        Driver::Cargo => {
            let _cargo_guard = lock_nested_cargo();
            run_cargo_case(&binaries.cargo, &root, name, case)
        }
    };
    assert_eq!(
        output.status.code(),
        Some(case.exit_code),
        "{} ({}/{}): command exited {:?}, expected {}\nstdout:\n{}\nstderr:\n{}",
        name,
        fixture_name,
        case.behavior,
        output.status.code(),
        case.exit_code,
        output.stdout,
        output.stderr
    );
    if case.driver == Driver::Cargo && case.exit_code != 0 {
        assert!(
            output.stderr.contains("error:"),
            "{} ({}/{}): denied findings must fail through rustc/Cargo\nstderr:\n{}",
            name,
            fixture_name,
            case.behavior,
            output.stderr
        );
    }

    parse_messages(&output, &root, sysroot, name, fixture_name, case)
}

fn parse_messages(
    output: &CommandOutput,
    root: &Path,
    sysroot: &str,
    name: &str,
    fixture_name: &str,
    case: &Case,
) -> Vec<Value> {
    let mut messages = output
        .stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let mut value = serde_json::from_str::<Value>(line).unwrap_or_else(|error| {
                panic!(
                    "{} ({}/{}): invalid JSON line: {error}\n{line}",
                    name, fixture_name, case.behavior
                )
            });
            normalize_json(&mut value, root, sysroot.trim());
            assert_finding_discriminators(&value);
            value
        })
        .collect::<Vec<_>>();
    assert!(
        !messages.is_empty(),
        "{} ({}/{}): no JSON messages emitted",
        name,
        fixture_name,
        case.behavior
    );

    // Ordering is not the contract here; Cargo/rustc can interleave reports.
    messages.sort_by_key(message_sort_key);
    messages
}

fn assert_finding_discriminators(report: &Value) {
    let Some(findings) = report.get("findings").and_then(Value::as_array) else {
        return;
    };
    for finding in findings {
        let kind = finding["kind"]
            .as_str()
            .expect("finding kind should be a string");
        assert!(
            finding.get("effect").is_none(),
            "finding `{kind}` should be discriminated by kind, not a redundant effect field: \
             {finding}"
        );
        assert!(
            !matches!(
                kind,
                "cached-dependency-panic"
                    | "ambiguous-effect-marker"
                    | "ambiguous-effect-requirement"
                    | "analysis-incomplete"
            ),
            "finding `{kind}` must use the workspace interpreter's policy-domain discriminator: \
             {finding}"
        );
    }
}

fn run_cargo_case(binary: &Path, root: &Path, name: &str, case: &Case) -> CommandOutput {
    let crate_dir = root.join(case.crate_dir);
    let mut command = Command::new(binary);
    clean_cargo_package_env(&mut command);
    let output = command
        .args(["--message-format", "json", "--color", "never"])
        .args(case.args)
        .current_dir(crate_dir)
        .output()
        .unwrap_or_else(|error| panic!("{name}: failed to run {}: {error}", binary.display()));
    CommandOutput::from_output(output)
}

fn run_direct_driver_case(
    binary: &Path,
    sysroot: &str,
    root: &Path,
    name: &str,
    fixture_name: &str,
    case: &Case,
) -> CommandOutput {
    let source = root.join(case.source);
    let crate_name = fixture_name.replace('-', "_");
    let crate_type = case.crate_type;
    let edition = case.edition;

    let mut command = Command::new(binary);
    clean_cargo_package_env(&mut command);
    if let Some(manifest) = case.manifest {
        command.args(["--manifest"]).arg(root.join(manifest));
    }
    let output = command
        .args(["--message-format", "json", "--color", "never"])
        .args(case.args)
        .arg("--")
        .args(["--crate-name", crate_name.as_str()])
        .args(["--crate-type", crate_type])
        .args(["--edition", edition])
        .arg(source)
        .args(["--sysroot", sysroot.trim(), "-Zno-codegen"])
        .current_dir(root)
        .output()
        .unwrap_or_else(|error| panic!("{name}: failed to run {}: {error}", binary.display()));
    CommandOutput::from_output(output)
}

fn normalize_json(value: &mut Value, fixture_root: &Path, sysroot: &str) {
    // Keep snapshots about report content, not run-local paths or fingerprints.
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if volatile_key(key) {
                    *value =
                        Value::String(format!("[{}]", key.to_ascii_uppercase().replace('-', "_")));
                } else {
                    normalize_json(value, fixture_root, sysroot);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                normalize_json(value, fixture_root, sysroot);
            }
        }
        Value::String(text) => {
            *text = text
                .replace(&fixture_root.display().to_string(), "[FIXTURE]")
                .replace(sysroot, "[SYSROOT]");
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn volatile_key(key: &str) -> bool {
    matches!(key, "artifact-id" | "rustc-version")
}

fn message_sort_key(message: &Value) -> (String, String) {
    let artifact = message.get("artifact").unwrap_or(&Value::Null);
    (
        json_string(message, "reason"),
        json_string(artifact, "crate-name"),
    )
}

fn json_string(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}
