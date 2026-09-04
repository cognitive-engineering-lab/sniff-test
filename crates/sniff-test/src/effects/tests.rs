use effect_tracing::{EffectEngine, TerminationSite, TraceOutcome};

use crate::annotations::AnnotationIndex;
use crate::artifact::{
    AnnotationFact, AnnotationFactKind, AnnotationProbingFact, AnnotationSatisfactionFact,
    AnnotationTargetFact, ArtifactFacts, CallFact, CallId, CallKindFact, CallSiteId,
    CallTargetFact, CompilerAssertKind, ContractFact, ContractRequirementFact, EffectFact,
    EffectFactKind, EffectId, FunctionAttributesFact, FunctionContractsFact, FunctionFact,
    FunctionFactProvenance, FunctionId as StableFunctionId, FunctionTargetFact,
    IndirectCallKindFact, MacroExpansionFact, MarkerId, OpaqueTargetFact, SafetyEffectGroupId,
    SafetyOpKind, SourceFileFact, SourceFileId, SourceRangeFact, StableInstanceHash,
};
use crate::compiler::invocations::InvocationGraph;
use crate::config::{MarkerProbing, SniffTestConfig};
use crate::contracts::ContractDocOverrides;
use crate::namespace::StableDefPathHash;

use super::comment::{CommentDomain, CommentEffect, CommentTermination};
use super::panic::{PanicEffect, PanicOrigin, PanicTermination};
use super::safety::{SafetyEffect, SafetyOrigin, SafetyTermination};

fn stable_function(index: u64) -> StableFunctionId {
    let value = format!("{index:016x}{:016x}", index + 100);
    let hash = serde_json::from_str::<StableDefPathHash>(&format!("\"{value}\""))
        .expect("valid stable hash");
    StableFunctionId::generic(hash)
}

fn exact_function(definition: StableFunctionId, index: u64) -> StableFunctionId {
    let value = format!("{index:016x}{:016x}", index + 200);
    let instance = serde_json::from_str::<StableInstanceHash>(&format!("\"{value}\""))
        .expect("valid stable instance hash");
    StableFunctionId::exact(definition.def_path_hash, instance)
}

fn attributes(path: &str) -> FunctionAttributesFact {
    FunctionAttributesFact {
        is_unsafe: false,
        is_exported: true,
        has_rust_body: true,
        is_foreign: false,
        namespace_candidates: vec![path.to_owned()],
    }
}

fn target(function: StableFunctionId, path: &str) -> CallTargetFact {
    CallTargetFact::Function(function_target(function, path))
}

fn function_target(function: StableFunctionId, path: &str) -> FunctionTargetFact {
    FunctionTargetFact {
        function,
        display_path: path.to_owned(),
        attributes: attributes(path),
        contracts: FunctionContractsFact::default(),
    }
}

fn unresolved_target(function: StableFunctionId, path: &str) -> CallTargetFact {
    CallTargetFact::OpaqueBoundary {
        description: String::from("unresolved function pointer call"),
        target: Some(OpaqueTargetFact::Function(FunctionTargetFact {
            function,
            display_path: path.to_owned(),
            attributes: attributes(path),
            contracts: FunctionContractsFact::default(),
        })),
    }
}

fn call(id: u32, site: u32, target: CallTargetFact, requires_unsafe: bool) -> CallFact {
    CallFact {
        id: CallId::new(id),
        call_site: CallSiteId::new(site),
        kind: CallKindFact::DirectCall,
        safety_effect_group: Some(SafetyEffectGroupId::new(site)),
        requires_unsafe,
        inside_builtin_unsafe: false,
        source_range: None,
        expanded_range: None,
        macro_expansions: Vec::new(),
        callee_range: None,
        indirect_kind: None,
        declaration_target: None,
        target,
    }
}

fn call_from_macro(id: u32, site: u32, target: CallTargetFact, macro_path: &str) -> CallFact {
    let mut call = call(id, site, target, false);
    call.macro_expansions.push(MacroExpansionFact {
        macro_def: stable_function(10_000 + u64::from(id)).def_path_hash,
        display_path: macro_path.to_owned(),
        source_range: None,
    });
    call
}

fn transparent_body(id: u32, site: u32, target: CallTargetFact) -> CallFact {
    let mut call = call(id, site, target, false);
    call.kind = CallKindFact::ConstBody;
    call
}

fn contract(
    id: u32,
    function: StableFunctionId,
    kind: AnnotationFactKind,
    requirements: &[(&str, &str)],
) -> AnnotationFact {
    AnnotationFact {
        id: MarkerId::new(id),
        identity: format!("contract-{id}"),
        kind,
        source_range: None,
        target: AnnotationTargetFact::Function(function),
        applicable_probing: vec![AnnotationProbingFact::SourceCallsite],
        satisfactions: Vec::new(),
        requirements: requirements
            .iter()
            .map(|(name, condition)| ContractRequirementFact {
                name: (*name).to_owned(),
                condition: (*condition).to_owned(),
                source_range: None,
            })
            .collect(),
    }
}

fn call_comment(
    id: u32,
    call: u32,
    kind: AnnotationFactKind,
    requirement: Option<&str>,
) -> AnnotationFact {
    AnnotationFact {
        id: MarkerId::new(id),
        identity: format!("comment-{id}"),
        kind,
        source_range: None,
        target: AnnotationTargetFact::Call(CallId::new(call)),
        applicable_probing: vec![AnnotationProbingFact::SourceCallsite],
        satisfactions: vec![AnnotationSatisfactionFact {
            requirement: requirement.map(str::to_owned),
            reason: String::from("audited reason"),
        }],
        requirements: Vec::new(),
    }
}

fn effect_comment(id: u32, effect: u32, kind: AnnotationFactKind) -> AnnotationFact {
    AnnotationFact {
        id: MarkerId::new(id),
        identity: format!("effect-comment-{id}"),
        kind,
        source_range: None,
        target: AnnotationTargetFact::Effect(EffectId::new(effect)),
        applicable_probing: vec![AnnotationProbingFact::SourceCallsite],
        satisfactions: vec![AnnotationSatisfactionFact {
            requirement: None,
            reason: String::from("audited reason"),
        }],
        requirements: Vec::new(),
    }
}

fn body(
    function: StableFunctionId,
    path: &str,
    calls: Vec<CallFact>,
    effects: Vec<EffectFact>,
    markers: Vec<AnnotationFact>,
) -> FunctionFact {
    FunctionFact {
        function,
        provenance: FunctionFactProvenance::DefiningArtifact,
        display_path: path.to_owned(),
        attributes: attributes(path),
        contract_declaration: None,
        source_range: None,
        calls,
        effects,
        markers,
        unverified_marker_probes: Vec::new(),
    }
}

fn assert_effect(id: u32) -> EffectFact {
    EffectFact {
        id: EffectId::new(id),
        safety_effect_group: None,
        source_range: None,
        expanded_range: None,
        macro_expansions: Vec::new(),
        kind: EffectFactKind::CompilerAssert {
            kind: CompilerAssertKind::BoundsCheck,
        },
    }
}

fn assert_effect_from_macro(id: u32, macro_path: &str) -> EffectFact {
    let mut effect = assert_effect(id);
    effect.macro_expansions.push(MacroExpansionFact {
        macro_def: stable_function(20_000 + u64::from(id)).def_path_hash,
        display_path: macro_path.to_owned(),
        source_range: None,
    });
    effect
}

fn unsafe_effect(id: u32) -> EffectFact {
    EffectFact {
        id: EffectId::new(id),
        safety_effect_group: Some(SafetyEffectGroupId::new(id)),
        source_range: None,
        expanded_range: None,
        macro_expansions: Vec::new(),
        kind: EffectFactKind::UnsafeOperation {
            kind: SafetyOpKind::DerefRawPointer,
        },
    }
}

fn unsafe_effect_from_macro(id: u32, macro_path: &str) -> EffectFact {
    let mut effect = unsafe_effect(id);
    effect.macro_expansions.push(MacroExpansionFact {
        macro_def: stable_function(30_000 + u64::from(id)).def_path_hash,
        display_path: macro_path.to_owned(),
        source_range: None,
    });
    effect
}

#[test]
fn exact_body_effects_are_seeded_only_in_their_own_instance() {
    let generic = stable_function(0);
    let first = exact_function(generic, 1);
    let second = exact_function(generic, 2);
    let (artifact, graph, annotations) = setup(vec![
        body(
            first,
            "sample::generic::<First>",
            Vec::new(),
            vec![assert_effect(0), unsafe_effect(1)],
            Vec::new(),
        ),
        body(
            second,
            "sample::generic::<Second>",
            Vec::new(),
            Vec::new(),
            Vec::new(),
        ),
    ]);
    let config = SniffTestConfig::default();

    let panic = probe_panic(&artifact, &graph, &annotations, &config.panics);
    let safety = probe_safety(&artifact, &graph, &annotations, &config.safety);

    assert_eq!(panic.source_count(), 1);
    assert_eq!(safety.source_count(), 1);
}

#[test]
fn generic_safety_operations_project_to_exact_consumer_bodies() {
    let generic = stable_function(0);
    let exact = exact_function(generic, 1);
    let generic_body = body(
        generic,
        "sample::generic",
        Vec::new(),
        vec![unsafe_effect(0)],
        Vec::new(),
    );
    let mut consumer_body = body(
        exact,
        "sample::generic::<Consumer>",
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    consumer_body.provenance = FunctionFactProvenance::ConsumerInstantiation {
        consumer_stable_crate_id: 7,
    };
    let (artifact, graph, annotations) = setup(vec![generic_body, consumer_body]);

    let safety = probe_safety(
        &artifact,
        &graph,
        &annotations,
        &crate::config::SafetyConfig::default(),
    );

    assert_eq!(safety.source_count(), 2);
}

fn setup(bodies: Vec<FunctionFact>) -> (ArtifactFacts, InvocationGraph, AnnotationIndex) {
    let artifact = ArtifactFacts::new(bodies, Vec::new()).expect("valid artifact facts");
    let graph = InvocationGraph::from_artifact(&artifact).expect("invocation graph");
    let annotations = AnnotationIndex::from_artifact(&artifact, &graph).expect("annotations");
    (artifact, graph, annotations)
}

#[test]
fn source_callsite_marker_projects_when_exact_call_id_differs() {
    let generic = stable_function(0);
    let exact = exact_function(generic, 1);
    let callee = stable_function(2);
    let file = SourceFileId::new("source");
    let range = |start, end| SourceRangeFact {
        file: file.clone(),
        byte_start: start,
        byte_end: end,
    };
    let mut unrelated = call(0, 0, target(callee, "sample::callee"), false);
    unrelated.source_range = Some(range(1, 2));
    let mut defining_call = call(1, 1, target(callee, "sample::callee"), false);
    defining_call.source_range = Some(range(10, 20));
    let mut exact_call = call(0, 9, target(callee, "sample::callee"), false);
    exact_call.source_range = Some(range(10, 20));
    let mut exact_body = body(
        exact,
        "sample::generic::<Exact>",
        vec![exact_call],
        Vec::new(),
        Vec::new(),
    );
    exact_body.provenance = FunctionFactProvenance::ConsumerInstantiation {
        consumer_stable_crate_id: 7,
    };
    let artifact = ArtifactFacts::new(
        vec![
            body(
                generic,
                "sample::generic",
                vec![unrelated, defining_call],
                Vec::new(),
                vec![call_comment(
                    0,
                    1,
                    AnnotationFactKind::PanicJustification,
                    None,
                )],
            ),
            exact_body,
            body(callee, "sample::callee", Vec::new(), Vec::new(), Vec::new()),
        ],
        vec![SourceFileFact {
            id: file,
            filename: String::from("src/lib.rs"),
            content_hash: String::from("sha256:test"),
            byte_len: 100,
        }],
    )
    .expect("valid artifact facts");
    let graph = InvocationGraph::from_artifact(&artifact).expect("invocation graph");
    let annotations = AnnotationIndex::from_artifact(&artifact, &graph).expect("annotations");
    let defining_invocation = graph
        .invocation_for_raw_call(generic, CallId::new(1))
        .expect("defining invocation");
    let exact_invocation = graph
        .invocation_for_raw_call(exact, CallId::new(0))
        .expect("exact invocation");

    assert!(
        graph
            .invocation_aliases(defining_invocation)
            .contains(&exact_invocation)
    );
    assert_eq!(
        annotations
            .comments_at_raw_call(
                exact_invocation,
                CallId::new(0),
                crate::annotations::AnnotationDomain::Panic,
            )
            .count(),
        1
    );
}

#[test]
fn marker_on_a_non_invocation_raw_edge_does_not_break_annotation_indexing() {
    let owner = stable_function(0);
    let target_function = stable_function(1);
    let mut compiler_assert = call(0, 0, target(target_function, "sample::assert"), false);
    compiler_assert.kind = CallKindFact::Assert;

    let (artifact, graph, _) = setup(vec![
        body(
            owner,
            "sample::owner",
            vec![compiler_assert],
            Vec::new(),
            vec![call_comment(
                0,
                0,
                AnnotationFactKind::SafetyJustification,
                None,
            )],
        ),
        body(
            target_function,
            "sample::assert",
            Vec::new(),
            Vec::new(),
            Vec::new(),
        ),
    ]);

    assert!(
        graph
            .invocation_for_raw_call(owner, CallId::new(0))
            .is_none(),
        "compiler assertions must remain effect sites, not source invocations"
    );
    assert_eq!(artifact.functions[0].markers.len(), 1);
}

fn trusted_comment_config() -> SniffTestConfig {
    SniffTestConfig::from_manifest_str(
        r#"
            [panics]
            trusted-boundary-namespaces = ["trusted::**"]

            [safety]
            trusted-boundary-namespaces = ["trusted::**"]
        "#,
    )
    .expect("trusted comment boundary configuration")
}

fn probe_comments<'a>(
    artifact: &ArtifactFacts,
    graph: &'a InvocationGraph,
    annotations: &'a AnnotationIndex,
    config: &SniffTestConfig,
) -> CommentEffect<'a> {
    let namespaces = artifact.definition_namespace_index();
    CommentEffect::probe(
        artifact,
        graph,
        annotations,
        &namespaces,
        &config.panics,
        &config.safety,
    )
}

fn probe_panic<'a>(
    artifact: &ArtifactFacts,
    graph: &'a InvocationGraph,
    annotations: &'a AnnotationIndex,
    config: &crate::config::PanicConfig,
) -> PanicEffect<'a> {
    let namespaces = artifact.definition_namespace_index();
    PanicEffect::probe(artifact, graph, annotations, &namespaces, config).expect("panic effect")
}

fn probe_safety<'a>(
    artifact: &ArtifactFacts,
    graph: &'a InvocationGraph,
    annotations: &'a AnnotationIndex,
    config: &crate::config::SafetyConfig,
) -> SafetyEffect<'a> {
    let namespaces = artifact.definition_namespace_index();
    SafetyEffect::probe(artifact, graph, annotations, &namespaces, config).expect("safety effect")
}

#[test]
fn function_contract_is_panic_termination_and_comment_source() {
    let root = stable_function(0);
    let leaf = stable_function(1);
    let (artifact, graph, annotations) = setup(vec![
        body(
            root,
            "sample::root",
            vec![call(0, 0, target(leaf, "sample::leaf"), false)],
            Vec::new(),
            Vec::new(),
        ),
        body(
            leaf,
            "sample::leaf",
            Vec::new(),
            vec![assert_effect(0)],
            vec![contract(
                0,
                leaf,
                AnnotationFactKind::PanicContract,
                &[("bounds", "the index is out of range")],
            )],
        ),
    ]);
    let config = SniffTestConfig::default();

    let panic = probe_panic(&artifact, &graph, &annotations, &config.panics);
    let comments = probe_comments(&artifact, &graph, &annotations, &config);
    let panic_trace = EffectEngine::new(&graph).trace(&panic);
    let comment_trace = EffectEngine::new(&graph.comment_graph()).trace(&comments);

    assert_eq!(
        panic_trace.outcomes().collect::<Vec<_>>(),
        vec![TraceOutcome::Handled(PanicOrigin::CompilerAssert {
            owner: leaf,
            effect: EffectId::new(0),
        })]
    );
    assert_eq!(comments.contract_count(CommentDomain::Panic), 1);
    assert_eq!(
        comment_trace.outcomes().collect::<Vec<_>>(),
        vec![TraceOutcome::Escaped(comments.contracts()[0].id())]
    );
}

#[test]
fn concrete_impl_without_contract_falls_back_to_trait_contract_per_domain() {
    let implementation = stable_function(0);
    let declaration = stable_function(1);
    let mut implementation_body = body(
        implementation,
        "sample::Impl::operation",
        Vec::new(),
        vec![assert_effect(0), unsafe_effect(1)],
        Vec::new(),
    );
    implementation_body.contract_declaration =
        Some(function_target(declaration, "sample::Trait::operation"));
    let (artifact, graph, annotations) = setup(vec![
        implementation_body,
        body(
            declaration,
            "sample::Trait::operation",
            Vec::new(),
            Vec::new(),
            vec![
                contract(0, declaration, AnnotationFactKind::PanicContract, &[]),
                contract(1, declaration, AnnotationFactKind::SafetyContract, &[]),
            ],
        ),
    ]);
    let config = SniffTestConfig::default();
    let implementation = graph.function(implementation).expect("concrete impl");

    for domain in [
        crate::annotations::AnnotationDomain::Panic,
        crate::annotations::AnnotationDomain::Safety,
    ] {
        assert_eq!(
            annotations
                .effective_contract(&graph, implementation, domain)
                .expect("trait fallback")
                .owner(),
            declaration
        );
    }

    let panic = probe_panic(&artifact, &graph, &annotations, &config.panics);
    let safety = probe_safety(&artifact, &graph, &annotations, &config.safety);
    let panic_trace = EffectEngine::new(&graph).trace(&panic);
    let safety_trace = EffectEngine::new(&graph).trace(&safety);

    assert_eq!(
        panic_trace.outcomes().collect::<Vec<_>>(),
        vec![TraceOutcome::Handled(PanicOrigin::CompilerAssert {
            owner: graph.stable_function(implementation),
            effect: EffectId::new(0),
        })]
    );
    let panic_handled = panic_trace.handled().collect::<Vec<_>>();
    assert_eq!(panic_handled.len(), 1);
    assert!(matches!(
        panic_handled[0].termination(),
        PanicTermination::Contract(_)
    ));

    assert_eq!(
        safety_trace.outcomes().collect::<Vec<_>>(),
        vec![TraceOutcome::Handled(SafetyOrigin::Operation {
            owner: graph.stable_function(implementation),
            effect: EffectId::new(1),
        })]
    );
    let safety_handled = safety_trace.handled().collect::<Vec<_>>();
    assert_eq!(safety_handled.len(), 1);
    assert!(matches!(
        safety_handled[0].termination(),
        SafetyTermination::Contract(_)
    ));
}

#[test]
fn concrete_impl_contract_overrides_trait_contract_only_in_its_domain() {
    let implementation = stable_function(0);
    let declaration = stable_function(1);
    let mut invokes_impl = call(
        0,
        0,
        target(implementation, "sample::Impl::operation"),
        false,
    );
    invokes_impl.declaration_target =
        Some(function_target(declaration, "sample::Trait::operation"));
    let (_, graph, annotations) = setup(vec![
        body(
            stable_function(2),
            "sample::root",
            vec![invokes_impl],
            Vec::new(),
            Vec::new(),
        ),
        body(
            implementation,
            "sample::Impl::operation",
            Vec::new(),
            Vec::new(),
            vec![contract(
                0,
                implementation,
                AnnotationFactKind::PanicContract,
                &[],
            )],
        ),
        body(
            declaration,
            "sample::Trait::operation",
            Vec::new(),
            Vec::new(),
            vec![
                contract(1, declaration, AnnotationFactKind::PanicContract, &[]),
                contract(2, declaration, AnnotationFactKind::SafetyContract, &[]),
            ],
        ),
    ]);
    let implementation = graph.function(implementation).expect("concrete impl");

    assert_eq!(
        annotations
            .effective_contract(
                &graph,
                implementation,
                crate::annotations::AnnotationDomain::Panic,
            )
            .expect("impl panic contract")
            .owner(),
        stable_function(0)
    );
    assert_eq!(
        annotations
            .effective_contract(
                &graph,
                implementation,
                crate::annotations::AnnotationDomain::Safety,
            )
            .expect("trait safety fallback")
            .owner(),
        declaration
    );
}

#[test]
fn declaration_contract_overrides_apply_without_a_declaration_body_or_call() {
    let implementation = stable_function(0);
    let declaration = stable_function(1);
    let mut implementation_body = body(
        implementation,
        "sample::Impl::operation",
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    implementation_body.contract_declaration =
        Some(function_target(declaration, "sample::Trait::operation"));
    let artifact = ArtifactFacts::new(vec![implementation_body], Vec::new()).expect("artifact");
    let graph = InvocationGraph::from_artifact(&artifact).expect("invocation graph");
    let overrides = ContractDocOverrides::new(vec![(
        String::from("sample::Trait::operation"),
        String::from("# Panics\n\nWhen the declared precondition is violated."),
    )])
    .expect("contract override");
    let namespaces = artifact.definition_namespace_index();
    let annotations = AnnotationIndex::from_artifact_with_overrides(
        &artifact,
        &graph,
        &namespaces,
        &overrides,
        MarkerProbing::SourceCallsite,
    )
    .expect("annotations");
    let implementation = graph.function(implementation).expect("implementation");

    assert_eq!(
        annotations
            .effective_contract(
                &graph,
                implementation,
                crate::annotations::AnnotationDomain::Panic,
            )
            .expect("declaration override")
            .owner(),
        declaration,
    );
}

#[test]
fn declaration_override_uses_union_of_all_occurrence_aliases() {
    fn selected_requirements(declaration_aliases: [&str; 2]) -> Vec<String> {
        let root = stable_function(0);
        let declaration = stable_function(1);
        let mut calls = [
            call(
                0,
                0,
                target(stable_function(2), "sample::First::operation"),
                false,
            ),
            call(
                1,
                1,
                target(stable_function(3), "sample::Second::operation"),
                false,
            ),
        ];
        for (call, alias) in calls.iter_mut().zip(declaration_aliases) {
            call.declaration_target = Some(function_target(declaration, alias));
        }
        let artifact = ArtifactFacts::new(
            vec![body(
                root,
                "sample::root",
                Vec::from(calls),
                Vec::new(),
                Vec::new(),
            )],
            Vec::new(),
        )
        .expect("artifact");
        let graph = InvocationGraph::from_artifact(&artifact).expect("invocation graph");
        let overrides = ContractDocOverrides::new(vec![
            (
                String::from("compat::**"),
                String::from("# Panics\n\nRequirements:\n- broad: broad override"),
            ),
            (
                String::from("canonical::Trait::operation"),
                String::from("# Panics\n\nRequirements:\n- specific: specific override"),
            ),
        ])
        .expect("contract overrides");
        let namespaces = artifact.definition_namespace_index();
        let annotations = AnnotationIndex::from_artifact_with_overrides(
            &artifact,
            &graph,
            &namespaces,
            &overrides,
            MarkerProbing::SourceCallsite,
        )
        .expect("annotations");

        annotations
            .function_contracts(declaration, crate::annotations::AnnotationDomain::Panic)
            .flat_map(crate::annotations::FunctionContractAnnotation::requirements)
            .map(|requirement| requirement.name.clone())
            .collect()
    }

    let broad = "compat::Trait::operation";
    let specific = "canonical::Trait::operation";

    assert_eq!(
        selected_requirements([broad, specific]),
        vec![String::from("specific")]
    );
    assert_eq!(
        selected_requirements([specific, broad]),
        vec![String::from("specific")]
    );
}

#[test]
fn declaration_edge_exports_only_its_own_surface_contract() {
    for (domain, kind) in [
        (CommentDomain::Panic, AnnotationFactKind::PanicContract),
        (CommentDomain::Safety, AnnotationFactKind::SafetyContract),
    ] {
        let root = stable_function(0);
        let declaration = stable_function(1);
        let helper = stable_function(2);
        let mut dynamic_call = call(
            0,
            0,
            CallTargetFact::OpaqueBoundary {
                description: String::from("unresolved dynamic dispatch"),
                target: Some(OpaqueTargetFact::Trait(function_target(
                    declaration,
                    "sample::Trait::operation",
                ))),
            },
            false,
        );
        dynamic_call.kind = CallKindFact::IndirectCall;
        dynamic_call.indirect_kind = Some(IndirectCallKindFact::DynamicDispatch);
        let (artifact, graph, annotations) = setup(vec![
            body(
                root,
                "sample::root",
                vec![dynamic_call],
                Vec::new(),
                Vec::new(),
            ),
            body(
                declaration,
                "sample::Trait::operation",
                vec![call(0, 0, target(helper, "sample::helper"), false)],
                Vec::new(),
                vec![contract(0, declaration, kind, &[])],
            ),
            body(
                helper,
                "sample::helper",
                Vec::new(),
                Vec::new(),
                vec![contract(1, helper, kind, &[])],
            ),
        ]);
        let config = SniffTestConfig::default();
        let comments = probe_comments(&artifact, &graph, &annotations, &config);
        let trace = EffectEngine::new(&graph.comment_graph()).trace(&comments);

        let declaration_node = graph.function(declaration).expect("declaration node");
        let surface = comments
            .contracts()
            .iter()
            .find(|contract| contract.applies_to(declaration_node))
            .expect("declaration surface contract")
            .id();
        assert_eq!(comments.contract_count(domain), 2, "domain {domain:?}");
        assert_eq!(
            trace.outcomes().collect::<Vec<_>>(),
            vec![TraceOutcome::Escaped(surface)],
            "only the declaration's own contract may cross its unresolved edge in {domain:?}",
        );
    }
}

#[test]
fn mixed_invocation_keeps_its_concrete_comment_edge() {
    for (domain, kind) in [
        (CommentDomain::Panic, AnnotationFactKind::PanicContract),
        (CommentDomain::Safety, AnnotationFactKind::SafetyContract),
    ] {
        let root = stable_function(0);
        let implementation = stable_function(1);
        let declaration = stable_function(2);
        let helper = stable_function(3);
        let concrete_edge = call(
            0,
            0,
            target(implementation, "sample::Impl::operation"),
            false,
        );
        let mut unresolved_edge = call(
            1,
            0,
            CallTargetFact::OpaqueBoundary {
                description: String::from("additional unresolved dynamic target"),
                target: Some(OpaqueTargetFact::Trait(function_target(
                    declaration,
                    "sample::Trait::operation",
                ))),
            },
            false,
        );
        unresolved_edge.kind = CallKindFact::IndirectCall;
        unresolved_edge.indirect_kind = Some(IndirectCallKindFact::DynamicDispatch);
        let (artifact, graph, annotations) = setup(vec![
            body(
                root,
                "sample::root",
                vec![concrete_edge, unresolved_edge],
                Vec::new(),
                Vec::new(),
            ),
            body(
                implementation,
                "sample::Impl::operation",
                vec![call(0, 0, target(helper, "sample::helper"), false)],
                Vec::new(),
                Vec::new(),
            ),
            body(
                declaration,
                "sample::Trait::operation",
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            body(
                helper,
                "sample::helper",
                Vec::new(),
                Vec::new(),
                vec![contract(0, helper, kind, &[])],
            ),
        ]);
        let config = SniffTestConfig::default();
        let comments = probe_comments(&artifact, &graph, &annotations, &config);

        let invocation = graph
            .invocation_for_raw_call(root, CallId::new(0))
            .expect("grouped concrete edge");
        assert_eq!(
            graph.invocation_for_raw_call(root, CallId::new(1)),
            Some(invocation),
            "the concrete and unresolved targets must share one source invocation"
        );
        assert_eq!(
            graph
                .invocation(invocation)
                .function_targets()
                .collect::<Vec<_>>(),
            vec![graph.function(implementation).expect("implementation")]
        );
        assert_eq!(
            graph
                .invocation(invocation)
                .declaration_targets()
                .collect::<Vec<_>>(),
            vec![graph.function(declaration).expect("declaration")]
        );
        let trace = EffectEngine::new(&graph.comment_graph()).trace(&comments);

        assert_eq!(comments.contract_count(domain), 1, "domain {domain:?}");
        assert_eq!(trace.escaped().count(), 1, "domain {domain:?}");
    }
}

#[test]
fn standalone_declaration_target_exports_its_surface_contract() {
    let root = stable_function(0);
    let declaration = stable_function(1);
    let mut declaration_target = function_target(declaration, "sample::Trait::operation");
    declaration_target.attributes.has_rust_body = false;
    declaration_target.contracts.panic = Some(ContractFact {
        source_range: None,
        requirements: Vec::new(),
    });
    let mut unresolved = call(
        0,
        0,
        CallTargetFact::OpaqueBoundary {
            description: String::from("unresolved generic dispatch"),
            target: None,
        },
        false,
    );
    unresolved.kind = CallKindFact::IndirectCall;
    unresolved.declaration_target = Some(declaration_target);
    let (artifact, graph, annotations) = setup(vec![body(
        root,
        "sample::root",
        vec![unresolved],
        Vec::new(),
        Vec::new(),
    )]);

    let comments = probe_comments(&artifact, &graph, &annotations, &SniffTestConfig::default());
    let trace = EffectEngine::new(&graph.comment_graph()).trace(&comments);

    assert_eq!(comments.contract_count(CommentDomain::Panic), 1);
    assert_eq!(trace.handled().count(), 0);
    assert_eq!(trace.escaped().count(), 1);
}

#[test]
fn comment_obligations_are_satisfied_across_call_levels() {
    let root = stable_function(0);
    let middle = stable_function(1);
    let leaf = stable_function(2);
    let (artifact, graph, annotations) = setup(vec![
        body(
            root,
            "sample::root",
            vec![call(0, 0, target(middle, "sample::middle"), false)],
            Vec::new(),
            vec![call_comment(
                0,
                0,
                AnnotationFactKind::SafetyJustification,
                Some("exclusive"),
            )],
        ),
        body(
            middle,
            "sample::middle",
            vec![call(0, 0, target(leaf, "sample::leaf"), false)],
            Vec::new(),
            vec![call_comment(
                0,
                0,
                AnnotationFactKind::SafetyJustification,
                Some("initialized"),
            )],
        ),
        body(
            leaf,
            "sample::leaf",
            Vec::new(),
            Vec::new(),
            vec![contract(
                0,
                leaf,
                AnnotationFactKind::SafetyContract,
                &[
                    ("initialized", "global state is initialized"),
                    ("exclusive", "no concurrent access"),
                ],
            )],
        ),
    ]);

    let config = SniffTestConfig::default();
    let comments = probe_comments(&artifact, &graph, &annotations, &config);
    let trace = EffectEngine::new(&graph.comment_graph()).trace(&comments);
    let source_invocation = graph
        .invocation_for_raw_call(middle, CallId::new(0))
        .expect("documented safety call");
    let partial_invocation = source_invocation;
    let final_invocation = graph
        .invocation_for_raw_call(root, CallId::new(0))
        .expect("outer safety call");
    let partial_marker = annotations
        .comments_at_raw_call(
            partial_invocation,
            CallId::new(0),
            crate::annotations::AnnotationDomain::Safety,
        )
        .next()
        .expect("partial marker")
        .id();
    let final_marker = annotations
        .comments_at_raw_call(
            final_invocation,
            CallId::new(0),
            crate::annotations::AnnotationDomain::Safety,
        )
        .next()
        .expect("final marker")
        .id();
    let marker_uses = comments.marker_uses(&trace);

    assert_eq!(comments.contract_count(CommentDomain::Safety), 1);
    assert_eq!(
        trace.outcomes().collect::<Vec<_>>(),
        vec![TraceOutcome::Handled(comments.contracts()[0].id())]
    );
    assert!(
        trace
            .nodes()
            .any(|node| node.state().remaining().len() == 1)
    );
    assert_eq!(marker_uses.len(), 2);
    assert!(
        marker_uses
            .iter()
            .all(|usage| usage.source_invocation() == source_invocation)
    );
    assert!(marker_uses.iter().any(|usage| {
        usage.annotation() == partial_marker && usage.invocation() == partial_invocation
    }));
    assert!(marker_uses.iter().any(|usage| {
        usage.annotation() == final_marker && usage.invocation() == final_invocation
    }));
}

#[test]
fn trusted_comment_boundaries_are_path_local_in_each_domain() {
    for (domain, kind) in [
        (CommentDomain::Panic, AnnotationFactKind::PanicContract),
        (CommentDomain::Safety, AnnotationFactKind::SafetyContract),
    ] {
        let outer_root = stable_function(0);
        let direct_root = stable_function(1);
        let wrapper = stable_function(2);
        let leaf = stable_function(3);
        let (artifact, graph, annotations) = setup(vec![
            body(
                outer_root,
                "sample::outer_root",
                vec![call(0, 0, target(wrapper, "trusted::wrapper"), false)],
                Vec::new(),
                Vec::new(),
            ),
            body(
                direct_root,
                "sample::direct_root",
                vec![call(0, 0, target(leaf, "trusted::leaf"), false)],
                Vec::new(),
                Vec::new(),
            ),
            body(
                wrapper,
                "trusted::wrapper",
                vec![call(0, 0, target(leaf, "trusted::leaf"), false)],
                Vec::new(),
                Vec::new(),
            ),
            body(
                leaf,
                "trusted::leaf",
                Vec::new(),
                Vec::new(),
                vec![contract(0, leaf, kind, &[])],
            ),
        ]);
        let config = trusted_comment_config();

        let comments = probe_comments(&artifact, &graph, &annotations, &config);
        let trace = EffectEngine::new(&graph.comment_graph()).trace(&comments);

        assert_eq!(comments.contract_count(domain), 1, "domain {domain:?}");
        let handled = trace.handled().next().expect("trusted boundary handling");
        assert_eq!(
            handled.termination(),
            &CommentTermination::TrustedBoundary,
            "domain {domain:?}"
        );
        assert_eq!(
            handled.site(),
            &TerminationSite::Function(graph.function(wrapper).unwrap()),
            "domain {domain:?}"
        );
        assert_eq!(trace.handled().count(), 1, "domain {domain:?}");
        assert_eq!(trace.escaped().count(), 1, "domain {domain:?}");
    }
}

#[test]
fn callsite_satisfaction_precedes_a_trusted_comment_boundary() {
    let wrapper = stable_function(0);
    let leaf = stable_function(1);
    let (artifact, graph, annotations) = setup(vec![
        body(
            wrapper,
            "trusted::wrapper",
            vec![call(0, 0, target(leaf, "dependency::leaf"), false)],
            Vec::new(),
            vec![call_comment(
                0,
                0,
                AnnotationFactKind::SafetyJustification,
                None,
            )],
        ),
        body(
            leaf,
            "dependency::leaf",
            Vec::new(),
            Vec::new(),
            vec![contract(1, leaf, AnnotationFactKind::SafetyContract, &[])],
        ),
    ]);
    let config = trusted_comment_config();
    let comments = probe_comments(&artifact, &graph, &annotations, &config);
    let trace = EffectEngine::new(&graph.comment_graph()).trace(&comments);
    let handled = trace.handled().next().expect("callsite satisfaction");

    assert!(matches!(
        handled.termination(),
        CommentTermination::Satisfaction(_)
    ));
    assert!(matches!(handled.site(), TerminationSite::Invocation(_)));
}

#[test]
fn partial_satisfaction_is_retained_when_the_trusted_parent_terminates() {
    let wrapper = stable_function(0);
    let leaf = stable_function(1);
    let (artifact, graph, annotations) = setup(vec![
        body(
            wrapper,
            "trusted::wrapper",
            vec![call(0, 0, target(leaf, "dependency::leaf"), false)],
            Vec::new(),
            vec![call_comment(
                0,
                0,
                AnnotationFactKind::SafetyJustification,
                Some("initialized"),
            )],
        ),
        body(
            leaf,
            "dependency::leaf",
            Vec::new(),
            Vec::new(),
            vec![contract(
                1,
                leaf,
                AnnotationFactKind::SafetyContract,
                &[
                    ("initialized", "global state is initialized"),
                    ("exclusive", "no concurrent access"),
                ],
            )],
        ),
    ]);
    let config = trusted_comment_config();
    let comments = probe_comments(&artifact, &graph, &annotations, &config);
    let trace = EffectEngine::new(&graph.comment_graph()).trace(&comments);
    let handled = trace.handled().next().expect("trusted parent termination");
    let node = trace
        .nodes()
        .nth(handled.node().expect("parent node").index())
        .expect("handled trace node");

    assert_eq!(handled.termination(), &CommentTermination::TrustedBoundary);
    assert_eq!(
        handled.site(),
        &TerminationSite::Function(graph.function(wrapper).unwrap())
    );
    assert_eq!(node.state().remaining().len(), 1);
}

#[test]
fn builtin_unsafe_comment_edges_remain_ignored_inside_a_trusted_parent() {
    let wrapper = stable_function(0);
    let leaf = stable_function(1);
    let mut builtin_call = call(0, 0, target(leaf, "dependency::leaf"), false);
    builtin_call.inside_builtin_unsafe = true;
    let (artifact, graph, annotations) = setup(vec![
        body(
            wrapper,
            "trusted::wrapper",
            vec![builtin_call],
            Vec::new(),
            Vec::new(),
        ),
        body(
            leaf,
            "dependency::leaf",
            Vec::new(),
            Vec::new(),
            vec![contract(0, leaf, AnnotationFactKind::SafetyContract, &[])],
        ),
    ]);
    let config = trusted_comment_config();
    let comments = probe_comments(&artifact, &graph, &annotations, &config);
    let trace = EffectEngine::new(&graph.comment_graph()).trace(&comments);

    assert_eq!(comments.contract_count(CommentDomain::Safety), 1);
    assert_eq!(trace.nodes().count(), 1);
    assert_eq!(trace.handled().count(), 0);
    assert_eq!(trace.escaped().count(), 0);
}

#[test]
fn comment_boundaries_keep_panic_and_safety_configuration_separate() {
    let panic_wrapper = stable_function(0);
    let panic_leaf = stable_function(1);
    let safety_wrapper = stable_function(2);
    let safety_leaf = stable_function(3);
    let (artifact, graph, annotations) = setup(vec![
        body(
            panic_wrapper,
            "panic_boundary::wrapper",
            vec![call(
                0,
                0,
                target(panic_leaf, "dependency::panic_leaf"),
                false,
            )],
            Vec::new(),
            Vec::new(),
        ),
        body(
            panic_leaf,
            "dependency::panic_leaf",
            Vec::new(),
            Vec::new(),
            vec![contract(
                0,
                panic_leaf,
                AnnotationFactKind::PanicContract,
                &[],
            )],
        ),
        body(
            safety_wrapper,
            "safety_boundary::wrapper",
            vec![call(
                0,
                0,
                target(safety_leaf, "dependency::safety_leaf"),
                false,
            )],
            Vec::new(),
            Vec::new(),
        ),
        body(
            safety_leaf,
            "dependency::safety_leaf",
            Vec::new(),
            Vec::new(),
            vec![contract(
                1,
                safety_leaf,
                AnnotationFactKind::SafetyContract,
                &[],
            )],
        ),
    ]);
    let config = SniffTestConfig::from_manifest_str(
        r#"
            [panics]
            trusted-boundary-namespaces = ["panic_boundary::**"]

            [safety]
            trusted-boundary-namespaces = ["safety_boundary::**"]
        "#,
    )
    .expect("separate domain boundaries");

    let comments = probe_comments(&artifact, &graph, &annotations, &config);
    let trace = EffectEngine::new(&graph.comment_graph()).trace(&comments);
    assert_eq!(comments.contract_count(CommentDomain::Panic), 1);
    assert_eq!(comments.contract_count(CommentDomain::Safety), 1);
    assert_eq!(trace.handled().count(), 2);
    assert!(
        trace
            .handled()
            .all(|handled| handled.termination() == &CommentTermination::TrustedBoundary)
    );
    assert_eq!(trace.escaped().count(), 0);
}

#[test]
fn comment_boundaries_use_stable_candidates_and_cover_function_aliases() {
    let generic_wrapper = stable_function(0);
    let exact_wrapper = exact_function(generic_wrapper, 1);
    let leaf = stable_function(2);
    let mut generic_body = body(
        generic_wrapper,
        "display::generic_wrapper",
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    generic_body.attributes.namespace_candidates = vec![String::from("trusted::stable_wrapper")];
    let mut exact_body = body(
        exact_wrapper,
        "display::generic_wrapper::<Consumer>",
        vec![call(
            0,
            0,
            target(leaf, "dependency::documented_leaf"),
            false,
        )],
        Vec::new(),
        Vec::new(),
    );
    exact_body.provenance = FunctionFactProvenance::ConsumerInstantiation {
        consumer_stable_crate_id: 7,
    };
    let (artifact, graph, annotations) = setup(vec![
        generic_body,
        exact_body,
        body(
            leaf,
            "dependency::documented_leaf",
            Vec::new(),
            Vec::new(),
            vec![contract(0, leaf, AnnotationFactKind::PanicContract, &[])],
        ),
    ]);
    let config = SniffTestConfig::from_manifest_str(
        "[panics]\ntrusted-boundary-namespaces = [\"trusted::**\"]\n",
    )
    .expect("stable candidate boundary");

    let comments = probe_comments(&artifact, &graph, &annotations, &config);
    let trace = EffectEngine::new(&graph.comment_graph()).trace(&comments);
    let handled = trace.handled().next().expect("exact alias termination");

    assert_eq!(handled.termination(), &CommentTermination::TrustedBoundary);
    assert_eq!(
        handled.site(),
        &TerminationSite::Function(graph.function(exact_wrapper).unwrap())
    );
    assert_eq!(trace.escaped().count(), 0);
}

#[test]
fn target_only_alias_makes_definition_opaque_for_all_effect_domains() {
    let root = stable_function(0);
    let boundary = stable_function(1);
    let documented_leaf = stable_function(2);
    let (artifact, graph, annotations) = setup(vec![
        body(
            root,
            "sample::root",
            vec![call(0, 0, target(boundary, "trusted::boundary"), false)],
            Vec::new(),
            Vec::new(),
        ),
        body(
            boundary,
            "dependency::boundary",
            vec![call(
                0,
                0,
                target(documented_leaf, "dependency::documented_leaf"),
                false,
            )],
            vec![assert_effect(0), unsafe_effect(1)],
            Vec::new(),
        ),
        body(
            documented_leaf,
            "dependency::documented_leaf",
            Vec::new(),
            Vec::new(),
            vec![
                contract(0, documented_leaf, AnnotationFactKind::PanicContract, &[]),
                contract(1, documented_leaf, AnnotationFactKind::SafetyContract, &[]),
            ],
        ),
    ]);
    let config = SniffTestConfig::from_manifest_str(
        r#"
            [panics]
            trusted-boundary-namespaces = ["trusted::**"]

            [safety]
            trusted-boundary-namespaces = ["trusted::**"]
        "#,
    )
    .expect("trusted boundary configuration");

    let panic = probe_panic(&artifact, &graph, &annotations, &config.panics);
    let safety = probe_safety(&artifact, &graph, &annotations, &config.safety);
    let comments = probe_comments(&artifact, &graph, &annotations, &config);
    let panic_trace = EffectEngine::new(&graph).trace(&panic);
    let safety_trace = EffectEngine::new(&graph).trace(&safety);
    let comment_trace = EffectEngine::new(&graph.comment_graph()).trace(&comments);
    let boundary_node = graph.function(boundary).expect("boundary node");

    assert_eq!(panic_trace.handled().count(), 1);
    assert!(panic_trace.handled().all(|handled| {
        handled.site() == &TerminationSite::Function(boundary_node)
            && handled.termination() == &PanicTermination::TrustedBoundary
    }));
    assert_eq!(panic_trace.escaped().count(), 0);
    assert_eq!(safety_trace.handled().count(), 1);
    assert!(safety_trace.handled().all(|handled| {
        handled.site() == &TerminationSite::Function(boundary_node)
            && handled.termination() == &SafetyTermination::TrustedBoundary
    }));
    assert_eq!(safety_trace.escaped().count(), 0);
    assert_eq!(comment_trace.handled().count(), 2);
    assert!(comment_trace.handled().all(|handled| {
        handled.site() == &TerminationSite::Function(boundary_node)
            && handled.termination() == &CommentTermination::TrustedBoundary
    }));
    assert_eq!(comment_trace.escaped().count(), 0);
}

#[test]
fn target_only_alias_ignores_raw_effect_owners_in_both_domains() {
    let root = stable_function(0);
    let ignored_owner = stable_function(1);
    let (artifact, graph, annotations) = setup(vec![
        body(
            root,
            "sample::root",
            vec![call(
                0,
                0,
                target(ignored_owner, "ignored::generated_boundary"),
                false,
            )],
            Vec::new(),
            Vec::new(),
        ),
        body(
            ignored_owner,
            "dependency::generated_boundary",
            Vec::new(),
            vec![assert_effect(0), unsafe_effect(1)],
            Vec::new(),
        ),
    ]);
    let config = SniffTestConfig::from_manifest_str(
        r#"
            [panics]
            ignored-namespaces = ["ignored::**"]

            [safety]
            ignored-namespaces = ["ignored::**"]
        "#,
    )
    .expect("ignored namespace configuration");

    let panic = probe_panic(&artifact, &graph, &annotations, &config.panics);
    let safety = probe_safety(&artifact, &graph, &annotations, &config.safety);

    assert_eq!(panic.source_count(), 0);
    assert_eq!(safety.source_count(), 0);
}

#[test]
fn untrusted_contracts_do_not_cross_trusted_wrappers_in_either_domain() {
    for (domain, kind) in [
        (CommentDomain::Panic, AnnotationFactKind::PanicContract),
        (CommentDomain::Safety, AnnotationFactKind::SafetyContract),
    ] {
        let root = stable_function(0);
        let wrapper = stable_function(1);
        let leaf = stable_function(2);
        let (artifact, graph, annotations) = setup(vec![
            body(
                root,
                "sample::root",
                vec![call(0, 0, target(wrapper, "trusted::wrapper"), false)],
                Vec::new(),
                Vec::new(),
            ),
            body(
                wrapper,
                "trusted::wrapper",
                vec![call(0, 0, target(leaf, "dependency::leaf"), false)],
                Vec::new(),
                Vec::new(),
            ),
            body(
                leaf,
                "dependency::leaf",
                Vec::new(),
                Vec::new(),
                vec![contract(0, leaf, kind, &[])],
            ),
        ]);
        let config = trusted_comment_config();

        let comments = probe_comments(&artifact, &graph, &annotations, &config);
        let trace = EffectEngine::new(&graph.comment_graph()).trace(&comments);

        assert_eq!(comments.contract_count(domain), 1, "domain {domain:?}");
        assert_eq!(trace.handled().count(), 1, "domain {domain:?}");
        assert_eq!(trace.escaped().count(), 0, "domain {domain:?}");
    }
}

#[test]
fn comment_trusted_boundary_handles_transparent_body_parent() {
    let root = stable_function(0);
    let parent = stable_function(1);
    let transparent = stable_function(2);
    let leaf = stable_function(3);
    let (artifact, graph, annotations) = setup(vec![
        body(
            root,
            "sample::root",
            vec![call(0, 0, target(parent, "trusted::parent"), false)],
            Vec::new(),
            Vec::new(),
        ),
        body(
            parent,
            "trusted::parent",
            vec![transparent_body(
                0,
                0,
                target(transparent, "generated::constant"),
            )],
            Vec::new(),
            Vec::new(),
        ),
        body(
            transparent,
            "generated::constant",
            vec![call(0, 0, target(leaf, "dependency::leaf"), false)],
            Vec::new(),
            Vec::new(),
        ),
        body(
            leaf,
            "dependency::leaf",
            Vec::new(),
            Vec::new(),
            vec![contract(0, leaf, AnnotationFactKind::PanicContract, &[])],
        ),
    ]);
    let config = trusted_comment_config();

    let comments = probe_comments(&artifact, &graph, &annotations, &config);
    let trace = EffectEngine::new(&graph.comment_graph()).trace(&comments);

    let handled = trace
        .handled()
        .next()
        .expect("transparent boundary handling");
    assert_eq!(handled.termination(), &CommentTermination::TrustedBoundary);
    assert_eq!(
        handled.site(),
        &TerminationSite::Function(graph.function(parent).unwrap())
    );
    assert_eq!(trace.escaped().count(), 0);
}

#[test]
fn panic_probe_collects_asserts_and_sink_invocations_with_source_markers() {
    let root = stable_function(0);
    let panic_sink = stable_function(1);
    let (artifact, graph, annotations) = setup(vec![body(
        root,
        "sample::root",
        vec![call(
            0,
            0,
            target(panic_sink, "core::panicking::panic_fmt"),
            false,
        )],
        vec![assert_effect(0)],
        vec![
            call_comment(0, 0, AnnotationFactKind::PanicJustification, None),
            effect_comment(1, 0, AnnotationFactKind::PanicJustification),
        ],
    )]);
    let config = SniffTestConfig::from_manifest_str(
        "[panics]\npanic-sink-namespaces = [\"core::panicking::**\"]",
    )
    .unwrap();

    let panic = probe_panic(&artifact, &graph, &annotations, &config.panics);
    let trace = EffectEngine::new(&graph).trace(&panic);

    assert_eq!(panic.source_count(), 2);
    assert_eq!(trace.handled().count(), 2);
    assert!(
        trace
            .outcomes()
            .all(|outcome| matches!(outcome, TraceOutcome::Handled(_)))
    );
}

#[test]
fn marker_on_a_grouped_sibling_does_not_justify_a_panic_sink() {
    let root = stable_function(0);
    let ordinary = stable_function(1);
    let panic_sink = stable_function(2);
    let (artifact, graph, annotations) = setup(vec![body(
        root,
        "sample::root",
        vec![
            call(0, 0, target(ordinary, "sample::ordinary"), false),
            call(
                1,
                0,
                target(panic_sink, "core::panicking::panic_fmt"),
                false,
            ),
        ],
        Vec::new(),
        vec![call_comment(
            0,
            0,
            AnnotationFactKind::PanicJustification,
            None,
        )],
    )]);
    let config = SniffTestConfig::from_manifest_str(
        "[panics]\npanic-sink-namespaces = [\"core::panicking::**\"]",
    )
    .expect("panic sink configuration");

    let panic = probe_panic(&artifact, &graph, &annotations, &config.panics);
    let trace = EffectEngine::new(&graph).trace(&panic);

    assert_eq!(panic.source_count(), 1);
    assert_eq!(trace.handled().count(), 0);
    assert_eq!(trace.escaped().count(), 1);
}

#[test]
fn marker_on_a_grouped_sibling_does_not_justify_an_unsafe_call() {
    let root = stable_function(0);
    let ordinary = stable_function(1);
    let unsafe_target = stable_function(2);
    let (artifact, graph, annotations) = setup(vec![body(
        root,
        "sample::root",
        vec![
            call(0, 0, target(ordinary, "sample::ordinary"), false),
            call(1, 0, target(unsafe_target, "sample::unsafe_call"), true),
        ],
        Vec::new(),
        vec![call_comment(
            0,
            0,
            AnnotationFactKind::SafetyJustification,
            None,
        )],
    )]);

    let safety = probe_safety(
        &artifact,
        &graph,
        &annotations,
        &crate::config::SafetyConfig::default(),
    );
    let trace = EffectEngine::new(&graph).trace(&safety);

    assert_eq!(safety.source_count(), 1);
    assert_eq!(trace.handled().count(), 0);
    assert_eq!(trace.escaped().count(), 1);
}

#[test]
fn marker_on_a_grouped_sibling_does_not_satisfy_a_comment_contract() {
    let root = stable_function(0);
    let ordinary = stable_function(1);
    let documented = stable_function(2);
    let (artifact, graph, annotations) = setup(vec![
        body(
            root,
            "sample::root",
            vec![
                call(0, 0, target(ordinary, "sample::ordinary"), false),
                call(1, 0, target(documented, "sample::documented"), false),
            ],
            Vec::new(),
            vec![call_comment(
                0,
                0,
                AnnotationFactKind::PanicJustification,
                None,
            )],
        ),
        body(
            documented,
            "sample::documented",
            Vec::new(),
            Vec::new(),
            vec![contract(
                1,
                documented,
                AnnotationFactKind::PanicContract,
                &[],
            )],
        ),
    ]);

    let comments = probe_comments(&artifact, &graph, &annotations, &SniffTestConfig::default());
    let trace = EffectEngine::new(&graph.comment_graph()).trace(&comments);

    assert_eq!(comments.contract_count(CommentDomain::Panic), 1);
    assert_eq!(trace.handled().count(), 0);
    assert_eq!(trace.escaped().count(), 1);
}

#[test]
fn marker_on_a_grouped_sibling_does_not_terminate_propagated_effects() {
    for (is_panic, marker_kind) in [
        (true, AnnotationFactKind::PanicJustification),
        (false, AnnotationFactKind::SafetyJustification),
    ] {
        let root = stable_function(0);
        let ordinary = stable_function(1);
        let leaf = stable_function(2);
        let leaf_effects = if is_panic {
            vec![assert_effect(0)]
        } else {
            vec![unsafe_effect(0)]
        };
        let (artifact, graph, annotations) = setup(vec![
            body(
                root,
                "sample::root",
                vec![
                    call(0, 0, target(ordinary, "sample::ordinary"), false),
                    call(1, 0, target(leaf, "sample::leaf"), false),
                ],
                Vec::new(),
                vec![call_comment(0, 0, marker_kind, None)],
            ),
            body(leaf, "sample::leaf", Vec::new(), leaf_effects, Vec::new()),
        ]);

        if is_panic {
            let effect = probe_panic(
                &artifact,
                &graph,
                &annotations,
                &crate::config::PanicConfig::default(),
            );
            let trace = EffectEngine::new(&graph).trace(&effect);
            assert_eq!(trace.handled().count(), 0, "panic sibling marker");
            assert_eq!(trace.escaped().count(), 1, "panic sibling marker");
        } else {
            let effect = probe_safety(
                &artifact,
                &graph,
                &annotations,
                &crate::config::SafetyConfig::default(),
            );
            let trace = EffectEngine::new(&graph).trace(&effect);
            assert_eq!(trace.handled().count(), 0, "safety sibling marker");
            assert_eq!(trace.escaped().count(), 1, "safety sibling marker");
        }
    }
}

#[test]
fn distinct_markers_justify_each_grouped_panic_branch() {
    let root = stable_function(0);
    let leaf = stable_function(1);
    let (artifact, graph, annotations) = setup(vec![
        body(
            root,
            "sample::root",
            vec![
                call(0, 0, target(leaf, "sample::leaf"), false),
                call(1, 0, target(leaf, "sample::leaf"), false),
            ],
            Vec::new(),
            vec![
                call_comment(0, 0, AnnotationFactKind::PanicJustification, None),
                call_comment(1, 1, AnnotationFactKind::PanicJustification, None),
            ],
        ),
        body(
            leaf,
            "sample::leaf",
            Vec::new(),
            vec![assert_effect(0)],
            Vec::new(),
        ),
    ]);
    let invocation = graph
        .invocation_for_raw_call(root, CallId::new(0))
        .expect("first grouped branch");
    assert_eq!(
        graph.invocation_for_raw_call(root, CallId::new(1)),
        Some(invocation),
        "both raw calls must belong to the same invocation"
    );
    let markers = [CallId::new(0), CallId::new(1)].map(|call| {
        annotations
            .comments_at_raw_call(
                invocation,
                call,
                crate::annotations::AnnotationDomain::Panic,
            )
            .next()
            .expect("valid panic justification")
            .id()
    });
    assert_ne!(markers[0], markers[1]);

    let panic = probe_panic(
        &artifact,
        &graph,
        &annotations,
        &crate::config::PanicConfig::default(),
    );
    let trace = EffectEngine::new(&graph).trace(&panic);

    assert_eq!(panic.source_count(), 1);
    assert_eq!(trace.handled().count(), 1);
    assert_eq!(trace.escaped().count(), 0);
}

#[test]
fn distinct_markers_justify_each_grouped_safety_branch() {
    let root = stable_function(0);
    let leaf = stable_function(1);
    let (artifact, graph, annotations) = setup(vec![
        body(
            root,
            "sample::root",
            vec![
                call(0, 0, target(leaf, "sample::leaf"), false),
                call(1, 0, target(leaf, "sample::leaf"), false),
            ],
            Vec::new(),
            vec![
                call_comment(0, 0, AnnotationFactKind::SafetyJustification, None),
                call_comment(1, 1, AnnotationFactKind::SafetyJustification, None),
            ],
        ),
        body(
            leaf,
            "sample::leaf",
            Vec::new(),
            vec![unsafe_effect(0)],
            Vec::new(),
        ),
    ]);
    let invocation = graph
        .invocation_for_raw_call(root, CallId::new(0))
        .expect("first grouped branch");
    assert_eq!(
        graph.invocation_for_raw_call(root, CallId::new(1)),
        Some(invocation),
        "both raw calls must belong to the same invocation"
    );
    let markers = [CallId::new(0), CallId::new(1)].map(|call| {
        annotations
            .comments_at_raw_call(
                invocation,
                call,
                crate::annotations::AnnotationDomain::Safety,
            )
            .next()
            .expect("valid safety justification")
            .id()
    });
    assert_ne!(markers[0], markers[1]);

    let safety = probe_safety(
        &artifact,
        &graph,
        &annotations,
        &crate::config::SafetyConfig::default(),
    );
    let trace = EffectEngine::new(&graph).trace(&safety);

    assert_eq!(safety.source_count(), 1);
    assert_eq!(trace.handled().count(), 1);
    assert_eq!(trace.escaped().count(), 0);
}

#[test]
fn grouped_effect_sources_are_terminated_per_raw_branch() {
    let root = stable_function(0);
    let first = stable_function(1);
    let second = stable_function(2);
    let (panic_artifact, panic_graph, panic_annotations) = setup(vec![body(
        root,
        "sample::panic_root",
        vec![
            call(0, 0, target(first, "core::panicking::panic_fmt"), false),
            call(
                1,
                0,
                target(second, "core::panicking::panic_nounwind"),
                false,
            ),
        ],
        Vec::new(),
        vec![call_comment(
            0,
            0,
            AnnotationFactKind::PanicJustification,
            None,
        )],
    )]);
    let panic_config = SniffTestConfig::from_manifest_str(
        "[panics]\npanic-sink-namespaces = [\"core::panicking::**\"]",
    )
    .expect("panic sink configuration");
    let panic = probe_panic(
        &panic_artifact,
        &panic_graph,
        &panic_annotations,
        &panic_config.panics,
    );
    let panic_trace = EffectEngine::new(&panic_graph).trace(&panic);

    assert_eq!(panic.source_count(), 2);
    assert_eq!(panic_trace.handled().count(), 1);
    assert_eq!(panic_trace.escaped().count(), 1);

    let (safety_artifact, safety_graph, safety_annotations) = setup(vec![body(
        root,
        "sample::safety_root",
        vec![
            call(0, 0, target(first, "sample::first"), true),
            call(1, 0, target(second, "sample::second"), true),
        ],
        Vec::new(),
        vec![call_comment(
            0,
            0,
            AnnotationFactKind::SafetyJustification,
            None,
        )],
    )]);
    let safety = probe_safety(
        &safety_artifact,
        &safety_graph,
        &safety_annotations,
        &crate::config::SafetyConfig::default(),
    );
    let safety_trace = EffectEngine::new(&safety_graph).trace(&safety);

    assert_eq!(safety.source_count(), 2);
    assert_eq!(safety_trace.handled().count(), 1);
    assert_eq!(safety_trace.escaped().count(), 1);
}

#[test]
fn panic_sink_declaration_seeds_opaque_invocation() {
    let root = stable_function(0);
    let runtime_target = stable_function(1);
    let declaration = stable_function(2);
    let mut opaque_call = call(
        0,
        0,
        unresolved_target(runtime_target, "sample::opaque_runtime"),
        false,
    );
    opaque_call.kind = CallKindFact::IndirectCall;
    opaque_call.indirect_kind = Some(IndirectCallKindFact::DynamicDispatch);
    opaque_call.declaration_target =
        Some(function_target(declaration, "core::panicking::panic_fmt"));
    let (artifact, graph, annotations) = setup(vec![body(
        root,
        "sample::root",
        vec![opaque_call],
        Vec::new(),
        Vec::new(),
    )]);
    let config = SniffTestConfig::from_manifest_str(
        "[panics]\npanic-sink-namespaces = [\"core::panicking::**\"]",
    )
    .expect("panic sink configuration");

    let panic = probe_panic(&artifact, &graph, &annotations, &config.panics);
    let trace = EffectEngine::new(&graph).trace(&panic);
    let invocation = graph
        .invocation_for_raw_call(root, CallId::new(0))
        .expect("opaque invocation");

    assert_eq!(panic.source_count(), 1);
    assert_eq!(
        trace.outcomes().collect::<Vec<_>>(),
        vec![TraceOutcome::Escaped(PanicOrigin::Invocation {
            invocation,
            call: CallId::new(0),
        })]
    );
}

#[test]
fn ignored_macro_path_terminates_a_direct_panic_source() {
    let root = stable_function(0);
    let panic_sink = stable_function(1);
    let (artifact, graph, annotations) = setup(vec![body(
        root,
        "sample::root",
        vec![call_from_macro(
            0,
            0,
            target(panic_sink, "core::panicking::panic_nounwind_fmt"),
            "core::ub_checks::assert_unsafe_precondition",
        )],
        Vec::new(),
        Vec::new(),
    )]);
    let config = SniffTestConfig::from_manifest_str(
        "[panics]\npanic-sink-namespaces = [\"core::panicking::**\"]\n",
    )
    .unwrap();

    let panic = probe_panic(&artifact, &graph, &annotations, &config.panics);
    let trace = EffectEngine::new(&graph).trace(&panic);
    let invocation = graph
        .invocation_for_raw_call(root, CallId::new(0))
        .expect("panic sink invocation");
    assert_eq!(
        trace.outcomes().collect::<Vec<_>>(),
        vec![TraceOutcome::Handled(PanicOrigin::Invocation {
            invocation,
            call: CallId::new(0),
        })]
    );
    let handled = trace.handled().next().expect("source should terminate");

    assert_eq!(handled.node(), None);
    assert_eq!(handled.termination(), &PanicTermination::IgnoredBoundary);
    assert_eq!(trace.escaped().count(), 0);
}

#[test]
fn ignored_macro_path_terminates_a_compiler_assert_source() {
    let root = stable_function(0);
    let (artifact, graph, annotations) = setup(vec![body(
        root,
        "sample::root",
        Vec::new(),
        vec![assert_effect_from_macro(
            0,
            "core::ub_checks::assert_unsafe_precondition",
        )],
        Vec::new(),
    )]);

    let panic = probe_panic(
        &artifact,
        &graph,
        &annotations,
        &crate::config::PanicConfig::default(),
    );
    let trace = EffectEngine::new(&graph).trace(&panic);
    let handled = trace.handled().next().expect("source should terminate");

    assert_eq!(handled.node(), None);
    assert_eq!(handled.termination(), &PanicTermination::IgnoredBoundary);
    assert_eq!(trace.escaped().count(), 0);
}

#[test]
fn ignored_macro_path_does_not_export_an_internal_panic_contract() {
    let root = stable_function(0);
    let helper = stable_function(1);
    let (artifact, graph, annotations) = setup(vec![
        body(
            root,
            "sample::root",
            vec![call_from_macro(
                0,
                0,
                target(
                    helper,
                    "core::ptr::const_ptr::<impl *const T>::is_aligned_to",
                ),
                "core::ub_checks::assert_unsafe_precondition",
            )],
            Vec::new(),
            Vec::new(),
        ),
        body(
            helper,
            "core::ptr::const_ptr::<impl *const T>::is_aligned_to",
            Vec::new(),
            Vec::new(),
            vec![contract(
                0,
                helper,
                AnnotationFactKind::PanicContract,
                &[("alignment", "the alignment is not a power of two")],
            )],
        ),
    ]);

    let comments = probe_comments(&artifact, &graph, &annotations, &SniffTestConfig::default());
    let trace = EffectEngine::new(&graph.comment_graph()).trace(&comments);

    assert_eq!(comments.contract_count(CommentDomain::Panic), 1);
    assert_eq!(trace.nodes().count(), 1);
    assert_eq!(trace.handled().count(), 0);
    assert_eq!(trace.escaped().count(), 0);
}

#[test]
fn disabling_unsafe_precondition_ignore_exports_internal_panic_contracts() {
    let root = stable_function(0);
    let helper = stable_function(1);
    let (artifact, graph, annotations) = setup(vec![
        body(
            root,
            "sample::root",
            vec![call_from_macro(
                0,
                0,
                target(
                    helper,
                    "core::ptr::const_ptr::<impl *const T>::is_aligned_to",
                ),
                "core::ub_checks::assert_unsafe_precondition",
            )],
            Vec::new(),
            Vec::new(),
        ),
        body(
            helper,
            "core::ptr::const_ptr::<impl *const T>::is_aligned_to",
            Vec::new(),
            Vec::new(),
            vec![contract(
                0,
                helper,
                AnnotationFactKind::PanicContract,
                &[("alignment", "the alignment is not a power of two")],
            )],
        ),
    ]);
    let config = SniffTestConfig::from_manifest_str("[panics]\nignored-namespaces = []\n")
        .expect("empty ignored namespace list");

    let comments = probe_comments(&artifact, &graph, &annotations, &config);
    let trace = EffectEngine::new(&graph.comment_graph()).trace(&comments);

    assert_eq!(trace.escaped().count(), 1);
}

#[test]
fn explicit_empty_ignored_namespaces_restores_unsafe_precondition_panics() {
    let root = stable_function(0);
    let panic_sink = stable_function(1);
    let (artifact, graph, annotations) = setup(vec![body(
        root,
        "sample::root",
        vec![call_from_macro(
            0,
            0,
            target(panic_sink, "core::panicking::panic_nounwind_fmt"),
            "core::ub_checks::assert_unsafe_precondition",
        )],
        Vec::new(),
        Vec::new(),
    )]);
    let config = SniffTestConfig::from_manifest_str(
        r#"
            [panics]
            ignored-namespaces = []
            panic-sink-namespaces = ["core::panicking::**"]
        "#,
    )
    .expect("empty ignored namespace list");

    let panic = probe_panic(&artifact, &graph, &annotations, &config.panics);
    let trace = EffectEngine::new(&graph).trace(&panic);

    assert_eq!(trace.handled().count(), 0);
    assert_eq!(trace.escaped().count(), 1);
}

#[test]
fn ignored_macro_path_does_not_hide_an_unrelated_panic_in_the_same_function() {
    let root = stable_function(0);
    let panic_sink = stable_function(1);
    let (artifact, graph, annotations) = setup(vec![body(
        root,
        "sample::root",
        vec![
            call_from_macro(
                0,
                0,
                target(panic_sink, "core::panicking::panic_nounwind_fmt"),
                "core::ub_checks::assert_unsafe_precondition",
            ),
            call(
                1,
                1,
                target(panic_sink, "core::panicking::panic_fmt"),
                false,
            ),
        ],
        Vec::new(),
        Vec::new(),
    )]);
    let config = SniffTestConfig::from_manifest_str(
        "[panics]\npanic-sink-namespaces = [\"core::panicking::**\"]\n",
    )
    .expect("panic sink configuration");

    let panic = probe_panic(&artifact, &graph, &annotations, &config.panics);
    let trace = EffectEngine::new(&graph).trace(&panic);

    assert_eq!(trace.handled().count(), 1);
    assert_eq!(trace.escaped().count(), 1);
    assert_eq!(
        trace
            .handled()
            .next()
            .expect("macro-generated panic should be ignored")
            .termination(),
        &PanicTermination::IgnoredBoundary
    );
}

#[test]
fn more_specific_panic_sink_policy_prevents_trusted_owner_opacity() {
    let root = stable_function(0);
    let trusted_sink_owner = stable_function(1);
    let (artifact, graph, annotations) = setup(vec![
        body(
            root,
            "sample::root",
            vec![call(
                0,
                0,
                target(trusted_sink_owner, "trusted::panic_sink"),
                false,
            )],
            Vec::new(),
            Vec::new(),
        ),
        body(
            trusted_sink_owner,
            "trusted::panic_sink",
            Vec::new(),
            vec![assert_effect(0)],
            Vec::new(),
        ),
    ]);
    let config = SniffTestConfig::from_manifest_str(
        r#"
            [panics]
            trusted-boundary-namespaces = ["trusted::**"]
            panic-sink-namespaces = ["trusted::panic_sink"]
        "#,
    )
    .expect("overlapping panic policies");

    let panic = probe_panic(&artifact, &graph, &annotations, &config.panics);
    let trace = EffectEngine::new(&graph).trace(&panic);

    assert_eq!(panic.source_count(), 2);
    assert!(
        !panic.is_trusted_function(graph.function(trusted_sink_owner).expect("sink owner node"))
    );
    assert_eq!(trace.handled().count(), 0);
    assert_eq!(trace.escaped().count(), 2);
}

#[test]
fn ignored_macro_path_termination_is_path_local() {
    let boundary_root = stable_function(0);
    let ordinary_root = stable_function(1);
    let helper = stable_function(2);
    let panic_sink = stable_function(3);
    let (artifact, graph, annotations) = setup(vec![
        body(
            boundary_root,
            "sample::boundary_root",
            vec![call_from_macro(
                0,
                0,
                target(helper, "sample::helper"),
                "core::ub_checks::assert_unsafe_precondition",
            )],
            Vec::new(),
            Vec::new(),
        ),
        body(
            ordinary_root,
            "sample::ordinary_root",
            vec![call(0, 0, target(helper, "sample::helper"), false)],
            Vec::new(),
            Vec::new(),
        ),
        body(
            helper,
            "sample::helper",
            vec![call(
                0,
                0,
                target(panic_sink, "core::panicking::panic_nounwind"),
                false,
            )],
            Vec::new(),
            Vec::new(),
        ),
    ]);
    let config = SniffTestConfig::from_manifest_str(
        "[panics]\npanic-sink-namespaces = [\"core::panicking::**\"]\n",
    )
    .unwrap();

    let panic = probe_panic(&artifact, &graph, &annotations, &config.panics);
    let trace = EffectEngine::new(&graph).trace(&panic);

    assert_eq!(trace.handled().count(), 1);
    assert_eq!(trace.escaped().count(), 1);
    assert!(
        trace
            .handled()
            .all(|handled| { handled.termination() == &PanicTermination::IgnoredBoundary })
    );
}

#[test]
fn panic_ignored_macro_path_does_not_suppress_safety_effects() {
    let root = stable_function(0);
    let macro_path = "core::ub_checks::assert_unsafe_precondition";
    let (artifact, graph, annotations) = setup(vec![body(
        root,
        "sample::root",
        Vec::new(),
        vec![
            assert_effect_from_macro(0, macro_path),
            unsafe_effect_from_macro(1, macro_path),
        ],
        Vec::new(),
    )]);

    let panic = probe_panic(
        &artifact,
        &graph,
        &annotations,
        &crate::config::PanicConfig::default(),
    );
    let safety = probe_safety(
        &artifact,
        &graph,
        &annotations,
        &crate::config::SafetyConfig::default(),
    );
    let panic_trace = EffectEngine::new(&graph).trace(&panic);
    let safety_trace = EffectEngine::new(&graph).trace(&safety);

    assert_eq!(panic_trace.handled().count(), 1);
    assert_eq!(panic_trace.escaped().count(), 0);
    assert_eq!(safety.source_count(), 1);
    assert_eq!(safety_trace.handled().count(), 0);
    assert_eq!(safety_trace.escaped().count(), 1);
}

#[test]
fn safety_probe_collects_operations_and_unsafe_invocations_with_source_markers() {
    let root = stable_function(0);
    let unsafe_target = stable_function(1);
    let (artifact, graph, annotations) = setup(vec![body(
        root,
        "sample::root",
        vec![call(0, 0, target(unsafe_target, "sample::danger"), true)],
        vec![unsafe_effect(0)],
        vec![
            call_comment(0, 0, AnnotationFactKind::SafetyJustification, None),
            effect_comment(1, 0, AnnotationFactKind::SafetyJustification),
        ],
    )]);

    let safety = probe_safety(
        &artifact,
        &graph,
        &annotations,
        &crate::config::SafetyConfig::default(),
    );
    let trace = EffectEngine::new(&graph).trace(&safety);

    assert_eq!(safety.source_count(), 2);
    assert_eq!(trace.handled().count(), 2);
    assert!(trace.outcomes().all(|outcome| matches!(
        outcome,
        TraceOutcome::Handled(SafetyOrigin::Operation { .. } | SafetyOrigin::Invocation { .. })
    )));
}

#[test]
fn trusted_target_does_not_suppress_local_unsafe_invocation_source() {
    let root = stable_function(0);
    let trusted_api = stable_function(1);
    let (artifact, graph, annotations) = setup(vec![
        body(
            root,
            "sample::root",
            vec![call(0, 0, target(trusted_api, "trusted::danger"), true)],
            Vec::new(),
            Vec::new(),
        ),
        body(
            trusted_api,
            "trusted::danger",
            Vec::new(),
            Vec::new(),
            Vec::new(),
        ),
    ]);
    let config = SniffTestConfig::from_manifest_str(
        "[safety]\ntrusted-boundary-namespaces = [\"trusted::**\"]\n",
    )
    .expect("trusted safety boundary configuration");

    let safety = probe_safety(&artifact, &graph, &annotations, &config.safety);
    let trace = EffectEngine::new(&graph).trace(&safety);

    assert_eq!(safety.source_count(), 1);
    assert_eq!(trace.handled().count(), 0);
    assert_eq!(
        trace.outcomes().collect::<Vec<_>>(),
        vec![TraceOutcome::Escaped(SafetyOrigin::Invocation {
            invocation: graph.invocation_for_raw_call(root, CallId::new(0)).unwrap(),
            call: CallId::new(0),
        })]
    );
}

#[test]
fn trusted_function_owner_terminates_internal_safety_operation() {
    let root = stable_function(0);
    let trusted_owner = stable_function(1);
    let (artifact, graph, annotations) = setup(vec![
        body(
            root,
            "sample::root",
            vec![call(
                0,
                0,
                target(trusted_owner, "trusted::implementation"),
                false,
            )],
            Vec::new(),
            Vec::new(),
        ),
        body(
            trusted_owner,
            "trusted::implementation",
            Vec::new(),
            vec![unsafe_effect(0)],
            Vec::new(),
        ),
    ]);
    let config = SniffTestConfig::from_manifest_str(
        "[safety]\ntrusted-boundary-namespaces = [\"trusted::**\"]\n",
    )
    .expect("trusted safety boundary configuration");

    let safety = probe_safety(&artifact, &graph, &annotations, &config.safety);
    let trace = EffectEngine::new(&graph).trace(&safety);

    assert_eq!(safety.source_count(), 1);
    let handled = trace.handled().next().expect("trusted owner termination");
    assert_eq!(
        handled.site(),
        &TerminationSite::Function(graph.function(trusted_owner).unwrap())
    );
    assert_eq!(handled.termination(), &SafetyTermination::TrustedBoundary);
    assert_eq!(trace.escaped().count(), 0);
}

#[test]
fn unresolved_safe_calls_are_not_effect_sources_and_unsafe_calls_are_not_duplicated() {
    let safe_root = stable_function(0);
    let unsafe_root = stable_function(1);
    let opaque_target = stable_function(2);
    let (artifact, graph, annotations) = setup(vec![
        body(
            safe_root,
            "sample::safe_root",
            vec![call(
                0,
                0,
                unresolved_target(opaque_target, "sample::opaque"),
                false,
            )],
            Vec::new(),
            Vec::new(),
        ),
        body(
            unsafe_root,
            "sample::unsafe_root",
            vec![call(
                0,
                0,
                unresolved_target(opaque_target, "sample::opaque"),
                true,
            )],
            Vec::new(),
            Vec::new(),
        ),
    ]);
    let config = SniffTestConfig::default();

    let panic = probe_panic(&artifact, &graph, &annotations, &config.panics);
    let safety = probe_safety(&artifact, &graph, &annotations, &config.safety);

    assert_eq!(panic.source_count(), 0);
    assert_eq!(safety.source_count(), 1);
    assert!(matches!(
        EffectEngine::new(&graph).trace(&safety).outcomes().next(),
        Some(TraceOutcome::Escaped(SafetyOrigin::Invocation { .. }))
    ));
}
