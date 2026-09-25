use super::ReportEffect;
use super::{
    EffectEngine, Panic, Safety, annotation_probing_fact, append_call_trace,
    effect_marker_evidence, invocation_source_has_contract, obligation_marker_evidence,
    raw_call_marker_evidence, same_source_finding, trace_workspace,
};
use crate::annotations::AnnotationIndex;
use crate::artifact::{
    AnnotationFact, AnnotationFactKind, AnnotationProbingFact, AnnotationRole,
    AnnotationSatisfactionFact, AnnotationTargetFact, ArtifactFacts, CallFact, CallId,
    CallKindFact, CallSiteId, CallTargetFact, ContractFact, EffectContractFact, EffectFact,
    EffectGroupId, EffectId, EffectKey, EffectKind, FunctionAttributesFact, FunctionContractsFact,
    FunctionFact, FunctionFactProvenance, FunctionId, FunctionTargetFact, IndirectCallKindFact,
    InvocationEffectFact, MacroExpansionFact, MarkerEvidenceState, MarkerId, OpaqueTargetFact,
    SourceFileFact, SourceFileId, SourceRangeFact, StableDefPathHash, StableInstanceHash,
    UnverifiedMarkerProbeFact, UnverifiedMarkerProbeReason,
};
use crate::artifact_cache::{
    ArtifactAnalysisCache, ArtifactInfo, ArtifactScope, CacheExpectations, RustcArtifactId,
};
use crate::compiler::invocations::InvocationGraph;
use crate::config::{EffectConfig, MarkerProbing, SniffTestConfig};
use crate::effects::concrete::{probe_concrete_effect, probe_concrete_effect_for};
use crate::effects::{EffectMetadata, EffectSpec, annotation_kind, effect};
use crate::report_model::{
    DomainCompleteness, IncompleteReason, InterpretationRoot, InterpretedFinding,
    InterpretedFindingKind, InterpretedTrace, InterpretedTraceStep, InterpretedTraceStepKind,
    RootInterpretation,
};
use crate::report_roots::ReportRootKind;
use crate::workspace::{ArtifactAnalysisGraph, ExternArtifactInput};

struct Allocation;

struct AllocationPass;

impl crate::effects::visit::MirEffectPass for AllocationPass {}

impl EffectSpec for Allocation {
    const EFFECT_NAME: &'static str = "allocation";
    const OBLIGATION: &'static str = "Allocations";
    const JUSTIFICATION: &'static str = "ALLOCATION";

    fn default_config() -> EffectConfig {
        EffectConfig::default()
    }

    fn register_passes(registry: &mut crate::effects::visit::EffectPassRegistry) {
        registry.register_mir_pass::<Self>(Box::new(AllocationPass));
    }
}

struct SourceAllocation;

struct SourceAllocationPass;

impl crate::effects::visit::HirEffectPass for SourceAllocationPass {}

impl EffectSpec for SourceAllocation {
    const EFFECT_NAME: &'static str = "source-allocation";
    const OBLIGATION: &'static str = "Allocations";
    const JUSTIFICATION: &'static str = "ALLOCATION";

    fn default_config() -> EffectConfig {
        EffectConfig::default()
    }

    fn register_passes(registry: &mut crate::effects::visit::EffectPassRegistry) {
        registry.register_hir_pass::<Self>(Box::new(SourceAllocationPass));
    }
}

fn stable_function(index: u64) -> FunctionId {
    let value = format!("{index:016x}{:016x}", index + 100);
    let hash = serde_json::from_str::<StableDefPathHash>(&format!("\"{value}\""))
        .expect("valid stable hash");
    FunctionId::generic(hash)
}

#[test]
fn registered_effect_gets_default_concrete_reporting_without_an_adapter() {
    let root = stable_function(9_900);
    let artifact = ArtifactFacts::new(
        vec![body(
            root,
            "sample::allocates",
            Vec::new(),
            vec![EffectFact {
                id: EffectId::new(0),
                effect: EffectKey::new(Allocation::EFFECT_NAME),
                effect_group: None,
                source_range: None,
                expanded_range: None,
                macro_expansions: Vec::new(),
                kind: EffectKind::new("heap-allocation"),
            }],
            Vec::new(),
            Vec::new(),
        )],
        Vec::new(),
    )
    .expect("custom effect artifact");
    let graph = InvocationGraph::from_artifact(&artifact).expect("invocation graph");
    let annotations = AnnotationIndex::from_artifact(&artifact, &graph).expect("annotations");
    let namespaces = artifact.definition_namespace_index();
    let allocation_config = crate::config::test_config().effect("panic").clone();
    let allocation = effect::<Allocation>(&allocation_config);
    let concrete = probe_concrete_effect(
        &artifact,
        &graph,
        &annotations,
        &namespaces,
        allocation.as_ref(),
    )
    .expect("custom concrete effect");
    let config = crate::config::test_config();
    let obligations = super::ObligationTracker::probe(
        &graph,
        &annotations,
        config.analysis.effect_doc_matching,
        [super::ObligationEffectPolicy::new(
            EffectKey::new(Allocation::EFFECT_NAME),
            concrete.trusted_functions(),
            concrete.ignored_invocations(),
        )],
    );
    let tracked = super::TrackedEffect::new(
        &concrete,
        &obligations,
        EffectKey::new(Allocation::EFFECT_NAME),
    );
    let obligation_graph = graph.obligation_graph();
    let trace = EffectEngine::new(&obligation_graph).trace(&tracked);
    let findings = super::concrete_findings(
        &artifact,
        &graph,
        &annotations,
        &EffectMetadata::of::<Allocation>(),
        &concrete,
        &trace,
        graph.function(root).expect("root function"),
        AnnotationProbingFact::SourceCallsite,
    );

    assert!(matches!(
        findings.as_slice(),
        [InterpretedFinding {
            effect,
            kind: InterpretedFindingKind::Operation { operation },
            ..
        }] if effect.key.as_str() == "allocation" && operation.as_str() == "heap-allocation"
    ));
    assert!(matches!(
        findings[0].trace.steps.last(),
        Some(InterpretedTraceStep {
            kind: InterpretedTraceStepKind::EffectOperation,
            target_path: Some(target),
            ..
        }) if target == "heap allocation"
    ));
}

#[test]
fn invocation_fact_controls_documentation_policy_for_a_registered_effect() {
    fn findings(requires_documented_obligation: bool) -> Vec<InterpretedFinding> {
        let root = stable_function(9_910);
        let callee = stable_function(9_911);
        let mut invocation = call(0, target(callee, "sample::allocator"));
        invocation.invocation_effects.push(InvocationEffectFact {
            effect: EffectKey::new(Allocation::EFFECT_NAME),
            kind: EffectKind::new("heap-allocation-call"),
            effect_group: invocation.effect_group,
            requires_documented_obligation,
        });
        let artifact = ArtifactFacts::new(
            vec![
                body(
                    root,
                    "sample::root",
                    vec![invocation],
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
                body(
                    callee,
                    "sample::allocator",
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
            ],
            Vec::new(),
        )
        .expect("custom invocation artifact");
        let graph = InvocationGraph::from_artifact(&artifact).expect("invocation graph");
        let annotations = AnnotationIndex::from_artifact(&artifact, &graph).expect("annotations");
        let namespaces = artifact.definition_namespace_index();
        let allocation_config = crate::config::test_config().effect("panic").clone();
        let allocation = effect::<Allocation>(&allocation_config);
        let concrete = probe_concrete_effect(
            &artifact,
            &graph,
            &annotations,
            &namespaces,
            allocation.as_ref(),
        )
        .expect("allocation effect");
        let config = crate::config::test_config();
        let obligations = super::ObligationTracker::probe(
            &graph,
            &annotations,
            config.analysis.effect_doc_matching,
            [super::ObligationEffectPolicy::new(
                EffectKey::new(Allocation::EFFECT_NAME),
                concrete.trusted_functions(),
                concrete.ignored_invocations(),
            )],
        );
        let tracked = super::TrackedEffect::new(
            &concrete,
            &obligations,
            EffectKey::new(Allocation::EFFECT_NAME),
        );
        let obligation_graph = graph.obligation_graph();
        let trace = EffectEngine::new(&obligation_graph).trace(&tracked);
        super::concrete_findings(
            &artifact,
            &graph,
            &annotations,
            &EffectMetadata::of::<Allocation>(),
            &concrete,
            &trace,
            graph.function(root).expect("root function"),
            AnnotationProbingFact::SourceCallsite,
        )
    }

    assert!(matches!(
        findings(true).as_slice(),
        [InterpretedFinding {
            kind: InterpretedFindingKind::UndocumentedInvocation { operation },
            marker_evidence: None,
            ..
        }] if operation.as_str() == "heap-allocation-call"
    ));
    assert!(matches!(
        findings(false).as_slice(),
        [InterpretedFinding {
            kind: InterpretedFindingKind::Invocation { operation },
            marker_evidence: Some(_),
            ..
        }] if operation.as_str() == "heap-allocation-call"
    ));
}

#[test]
fn local_justification_does_not_hide_required_invocation_documentation() {
    let root = stable_function(9_920);
    let callee = stable_function(9_921);
    let mut invocation = call(0, target(callee, "sample::unsafe_callee"));
    mark_safety_invocation(&mut invocation);
    let artifact = ArtifactFacts::new(
        vec![
            body(
                root,
                "sample::root",
                vec![invocation],
                Vec::new(),
                vec![shared_justification_marker(
                    0,
                    "local-safety-justification",
                    annotation_kind::<Safety>(AnnotationRole::Justification),
                    AnnotationTargetFact::Call(CallId::new(0)),
                )],
                Vec::new(),
            ),
            body(
                callee,
                "sample::unsafe_callee",
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
        ],
        Vec::new(),
    )
    .expect("justified unsafe invocation artifact");
    let reports = trace_workspace(
        &artifact,
        root.def_path_hash.stable_crate_id(),
        &ArtifactAnalysisGraph::default(),
        &[InterpretationRoot {
            function: root,
            path: String::from("sample::root"),
            kind: ReportRootKind::Concrete,
        }],
        &crate::config::test_config(),
    )
    .expect("effect report");

    assert!(
        reports[0].findings.iter().any(|finding| matches!(
            finding.kind,
            InterpretedFindingKind::UndocumentedInvocation { .. }
        )),
        "findings: {:#?}",
        reports[0].findings
    );
}

fn function_in_crate(stable_crate_id: u64, index: u64) -> FunctionId {
    let value = format!("{stable_crate_id:016x}{index:016x}");
    let hash = serde_json::from_str::<StableDefPathHash>(&format!("\"{value}\""))
        .expect("valid stable hash");
    FunctionId::generic(hash)
}

fn exact_function(definition: FunctionId, index: u64) -> FunctionId {
    let value = format!("{index:016x}{:016x}", index + 200);
    let instance = serde_json::from_str::<StableInstanceHash>(&format!("\"{value}\""))
        .expect("valid stable instance hash");
    FunctionId::exact(definition.def_path_hash, instance)
}

fn source_finding_with_trace_call(caller: FunctionId, call: u32) -> InterpretedFinding {
    InterpretedFinding {
        effect: EffectMetadata::of::<Panic>(),
        kind: InterpretedFindingKind::Invocation {
            operation: EffectKind::new("configured-invocation"),
        },
        function: stable_function(90),
        function_path: String::from("sample::panic_source"),
        callee: None,
        source_range: None,
        contract_source_range: None,
        marker_evidence: None,
        trace: InterpretedTrace {
            steps: vec![InterpretedTraceStep {
                caller,
                caller_path: String::from("sample::caller"),
                call: CallId::new(call),
                marker_call: None,
                kind: InterpretedTraceStepKind::Reachability(CallKindFact::DirectCall),
                source_range: Some(SourceRangeFact {
                    file: SourceFileId::new("normalized-source"),
                    byte_start: 10,
                    byte_end: 20,
                }),
                target: Some(stable_function(90)),
                target_path: Some(String::from("sample::panic_source")),
            }],
        },
        missing_requirements: Vec::new(),
        requirements: Vec::new(),
    }
}

#[test]
fn source_finding_identity_distinguishes_calls_but_merges_instance_aliases() {
    let generic_caller = stable_function(91);
    let first = source_finding_with_trace_call(generic_caller, 1);
    let second = source_finding_with_trace_call(generic_caller, 2);
    assert!(
        !same_source_finding(&first, &second),
        "two calls in one body remain distinct even when their ranges normalize identically"
    );

    let first_instance = exact_function(generic_caller, 92);
    let second_instance = exact_function(generic_caller, 93);
    let first = source_finding_with_trace_call(first_instance, 1);
    let second = source_finding_with_trace_call(second_instance, 2);
    assert!(
        same_source_finding(&first, &second),
        "the same source call projected through two instances remains one finding"
    );
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

fn target(function: FunctionId, path: &str) -> CallTargetFact {
    CallTargetFact::Function(FunctionTargetFact {
        function,
        display_path: path.to_owned(),
        attributes: attributes(path),
        contracts: FunctionContractsFact::default(),
    })
}

fn bodyless_declaration(
    function: FunctionId,
    path: &str,
    contracts: FunctionContractsFact,
) -> CallTargetFact {
    let mut declaration_attributes = attributes(path);
    declaration_attributes.has_rust_body = false;
    CallTargetFact::OpaqueBoundary {
        description: format!("unresolved implementation of `{path}`"),
        target: Some(OpaqueTargetFact::Trait(FunctionTargetFact {
            function,
            display_path: path.to_owned(),
            attributes: declaration_attributes,
            contracts,
        })),
    }
}

fn whole_contract() -> ContractFact {
    ContractFact {
        source_range: None,
        requirements: Vec::new(),
    }
}

fn effect_contracts(
    panic: Option<ContractFact>,
    safety: Option<ContractFact>,
) -> FunctionContractsFact {
    let mut effects = Vec::new();
    if let Some(contract) = panic {
        effects.push(EffectContractFact {
            effect: ReportEffect::Panic.key(),
            contract,
        });
    }
    if let Some(contract) = safety {
        effects.push(EffectContractFact {
            effect: ReportEffect::Safety.key(),
            contract,
        });
    }
    FunctionContractsFact { effects }
}

fn call(id: u32, target: CallTargetFact) -> CallFact {
    CallFact {
        id: CallId::new(id),
        call_site: CallSiteId::new(0),
        kind: CallKindFact::DirectCall,
        effect_group: Some(EffectGroupId::new(0)),
        invocation_effects: Vec::new(),
        suppressed_by_compiler_context: false,
        source_range: None,
        expanded_range: None,
        macro_expansions: Vec::new(),
        callee_range: None,
        indirect_kind: None,
        declaration_target: None,
        target,
    }
}

fn mark_safety_invocation(call: &mut CallFact) {
    call.invocation_effects.push(InvocationEffectFact {
        effect: ReportEffect::Safety.key(),
        kind: EffectKind::new("unsafe-call"),
        effect_group: call.effect_group,
        requires_documented_obligation: true,
    });
}

fn mark_panic_invocation(call: &mut CallFact) {
    call.invocation_effects.push(InvocationEffectFact {
        effect: ReportEffect::Panic.key(),
        kind: EffectKind::new("configured-invocation"),
        effect_group: call.effect_group,
        requires_documented_obligation: false,
    });
}

fn indirect_call(id: u32, site: u32, target: CallTargetFact) -> CallFact {
    let mut call = call(id, target);
    call.call_site = CallSiteId::new(site);
    call.kind = CallKindFact::IndirectCall;
    call.indirect_kind = Some(IndirectCallKindFact::DynamicDispatch);
    call
}

fn targetless_call(id: u32, site: u32, description: &str) -> CallFact {
    let mut call = indirect_call(
        id,
        site,
        CallTargetFact::OpaqueBoundary {
            description: description.to_owned(),
            target: None,
        },
    );
    call.indirect_kind = Some(IndirectCallKindFact::FunctionPointer);
    call
}

fn trusted_declaration_config() -> SniffTestConfig {
    crate::config::test_from_manifest_str(
        r#"
[panic]
trusted-boundary-namespaces = ["trusted::**"]
[panic.coverage]
unresolved-call-target = "warn"
[safety]
trusted-boundary-namespaces = ["trusted::**"]
[safety.coverage]
unresolved-call-target = "warn"
"#,
    )
    .expect("trusted declaration configuration")
}

fn assert_trusted_surface_findings(reports: &[RootInterpretation]) {
    let findings = reports
        .iter()
        .flat_map(|report| &report.findings)
        .collect::<Vec<_>>();
    assert!(
        findings.iter().all(|finding| !matches!(
            finding.kind,
            InterpretedFindingKind::UnresolvedCallTarget { .. }
        )),
        "trusted declaration surfaces should suppress unresolved coverage: {findings:#?}",
    );
    assert_eq!(
        findings
            .iter()
            .filter(|finding| {
                finding.effect.justification == "PANIC"
                    && matches!(finding.kind, InterpretedFindingKind::DocumentedObligation)
            })
            .count(),
        2,
        "the declaration's panic contract must remain a ObligationTracker source",
    );
    assert_eq!(
        findings
            .iter()
            .filter(|finding| {
                finding.effect.justification == "SAFETY"
                    && matches!(finding.kind, InterpretedFindingKind::DocumentedObligation)
            })
            .count(),
        2,
        "the declaration's safety contract must remain a ObligationTracker source",
    );
}

fn marker(id: u32, kind: AnnotationFactKind, target: AnnotationTargetFact) -> AnnotationFact {
    AnnotationFact {
        id: MarkerId::new(id),
        identity: format!("marker-{id}"),
        kind,
        source_range: None,
        target,
        applicable_probing: vec![AnnotationProbingFact::SourceCallsite],
        satisfactions: Vec::new(),
        requirements: Vec::new(),
    }
}

fn shared_justification_marker(
    id: u32,
    identity: &str,
    kind: AnnotationFactKind,
    target: AnnotationTargetFact,
) -> AnnotationFact {
    let mut marker = marker(id, kind, target);
    marker.identity = identity.to_owned();
    marker
        .applicable_probing
        .push(AnnotationProbingFact::MacroDefinitionFirst);
    marker.satisfactions.push(AnnotationSatisfactionFact {
        requirement: None,
        reason: String::from("audited reason"),
        structural_path: None,
    });
    marker
}

fn unsafe_operation_with_provenance(id: u32, group: u32, macro_index: u64) -> EffectFact {
    EffectFact {
        id: EffectId::new(id),
        effect: EffectKey::new("safety"),
        effect_group: Some(EffectGroupId::new(group)),
        source_range: None,
        expanded_range: None,
        macro_expansions: ["outer", "inner"]
            .into_iter()
            .zip(0_u64..)
            .map(|(layer, offset)| MacroExpansionFact {
                macro_def: stable_function(macro_index + offset).def_path_hash,
                display_path: format!("sample::{layer}_unsafe_{id}"),
                source_range: None,
            })
            .collect(),
        kind: EffectKind::new("raw-pointer-dereference"),
    }
}

fn body(
    function: FunctionId,
    path: &str,
    calls: Vec<CallFact>,
    effects: Vec<EffectFact>,
    markers: Vec<AnnotationFact>,
    unverified_marker_probes: Vec<UnverifiedMarkerProbeFact>,
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
        unverified_marker_probes,
    }
}

fn loaded_dependency(stable_crate_id: u64, facts: ArtifactFacts) -> ArtifactAnalysisGraph {
    const TOOL_VERSION: &str = "report-test-tool";
    const RUSTC_VERSION: &str = "report-test-rustc";
    let directory = tempfile::tempdir().expect("dependency cache directory");
    let artifact_id = RustcArtifactId::new(stable_crate_id, format!("{stable_crate_id:032x}"));
    let cache = ArtifactAnalysisCache::new(
        TOOL_VERSION,
        RUSTC_VERSION,
        ArtifactInfo {
            id: artifact_id.clone(),
            crate_name: format!("dependency-{stable_crate_id}"),
            scope: ArtifactScope::Dependency,
        },
        Vec::new(),
        facts,
    )
    .expect("valid dependency cache");
    cache
        .write(directory.path())
        .expect("written dependency cache");
    let graph = ArtifactAnalysisGraph::load(
        directory.path(),
        &[ExternArtifactInput {
            name: format!("dependency_{stable_crate_id}"),
            artifact_id,
        }],
        &CacheExpectations {
            tool_version: TOOL_VERSION,
            rustc_version: RUSTC_VERSION,
        },
    );
    assert!(
        graph.is_complete(),
        "dependency graph: {:#?}",
        graph.failures().collect::<Vec<_>>()
    );
    graph
}

fn missing_body_targets(completeness: &DomainCompleteness) -> Vec<FunctionId> {
    completeness
        .reasons
        .iter()
        .filter_map(|reason| match reason {
            IncompleteReason::MissingBody { function, .. } => Some(*function),
            IncompleteReason::TraceDepth { .. } | IncompleteReason::TraceStateBudget { .. } => None,
        })
        .collect()
}

fn completeness_for(report: &RootInterpretation, effect: ReportEffect) -> &DomainCompleteness {
    &report.completeness.effects[&effect.key()]
}

fn desugared_declaration_body(
    base: u64,
    first_path: &str,
    first_has_contract: bool,
    second_path: &str,
) -> FunctionFact {
    let first_contracts = if first_has_contract {
        effect_contracts(Some(whole_contract()), None)
    } else {
        FunctionContractsFact::default()
    };
    body(
        stable_function(base),
        &format!("sample::root_{base}"),
        vec![
            indirect_call(
                0,
                0,
                bodyless_declaration(stable_function(base + 1), first_path, first_contracts),
            ),
            indirect_call(
                1,
                0,
                bodyless_declaration(
                    stable_function(base + 2),
                    second_path,
                    FunctionContractsFact::default(),
                ),
            ),
        ],
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
}

fn unresolved_panic_count(reports: &[RootInterpretation], root: FunctionId) -> usize {
    reports
        .iter()
        .find(|report| report.root.function == root)
        .expect("root report")
        .findings
        .iter()
        .filter(|finding| {
            finding.effect.key == ReportEffect::Panic.key()
                && matches!(
                    finding.kind,
                    InterpretedFindingKind::UnresolvedCallTarget { .. }
                )
        })
        .count()
}

fn marker_evidence_fixture() -> (ArtifactFacts, InvocationGraph, FunctionId) {
    let owner = stable_function(0);
    let first_target = stable_function(1);
    let second_target = stable_function(2);
    let artifact = ArtifactFacts::new(
        vec![
            body(
                owner,
                "sample::owner",
                vec![
                    call(0, target(first_target, "sample::first_target")),
                    call(1, target(second_target, "sample::second_target")),
                ],
                vec![
                    EffectFact {
                        id: EffectId::new(0),
                        effect: EffectKey::new("panic"),
                        effect_group: None,
                        source_range: None,
                        expanded_range: None,
                        macro_expansions: Vec::new(),
                        kind: EffectKind::new("bounds-check"),
                    },
                    EffectFact {
                        id: EffectId::new(1),
                        effect: EffectKey::new("safety"),
                        effect_group: Some(EffectGroupId::new(1)),
                        source_range: None,
                        expanded_range: None,
                        macro_expansions: Vec::new(),
                        kind: EffectKind::new("raw-pointer-dereference"),
                    },
                ],
                vec![
                    marker(
                        0,
                        annotation_kind::<Panic>(AnnotationRole::Justification),
                        AnnotationTargetFact::Call(CallId::new(1)),
                    ),
                    marker(
                        1,
                        annotation_kind::<Panic>(AnnotationRole::Justification),
                        AnnotationTargetFact::Effect(EffectId::new(0)),
                    ),
                    marker(
                        2,
                        annotation_kind::<Safety>(AnnotationRole::Justification),
                        AnnotationTargetFact::Effect(EffectId::new(1)),
                    ),
                ],
                vec![UnverifiedMarkerProbeFact {
                    kind: annotation_kind::<Safety>(AnnotationRole::Justification),
                    target: AnnotationTargetFact::Call(CallId::new(0)),
                    probing: AnnotationProbingFact::SourceCallsite,
                    reason: UnverifiedMarkerProbeReason::SourceUnavailable,
                }],
            ),
            body(
                first_target,
                "sample::first_target",
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            body(
                second_target,
                "sample::second_target",
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
        ],
        Vec::new(),
    )
    .expect("valid marker evidence fixture");
    let graph = InvocationGraph::from_artifact(&artifact).expect("invocation graph");
    (artifact, graph, owner)
}

#[test]
fn active_marker_probing_maps_to_the_persisted_probe_mode() {
    assert_eq!(
        annotation_probing_fact(MarkerProbing::SourceCallsite),
        AnnotationProbingFact::SourceCallsite
    );
    assert_eq!(
        annotation_probing_fact(MarkerProbing::MacroDefinitionFirst),
        AnnotationProbingFact::MacroDefinitionFirst
    );
}

#[test]
fn only_real_invocation_trace_steps_retain_the_marker_call() {
    let owner = stable_function(0);
    let invoked = stable_function(1);
    let mut edge = call(7, target(invoked, "sample::invoked"));
    edge.macro_expansions.push(MacroExpansionFact {
        macro_def: stable_function(2).def_path_hash,
        display_path: String::from("sample::wrapper"),
        source_range: None,
    });
    let artifact = ArtifactFacts::new(
        vec![
            body(
                owner,
                "sample::owner",
                vec![edge.clone()],
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            body(
                invoked,
                "sample::invoked",
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
        ],
        Vec::new(),
    )
    .expect("valid trace fixture");
    let mut trace = crate::report_model::InterpretedTrace { steps: Vec::new() };

    append_call_trace(&artifact, owner, &edge, &mut trace);

    assert_eq!(trace.steps.len(), 2);
    assert_eq!(trace.steps[0].marker_call, None);
    assert_eq!(trace.steps[1].marker_call, Some(CallId::new(7)));
}

#[test]
fn source_findings_project_marker_evidence_by_exact_effect_or_raw_call() {
    let (artifact, graph, owner) = marker_evidence_fixture();
    let invocation = graph
        .invocation_for_raw_call(owner, CallId::new(0))
        .expect("source invocation");
    assert_eq!(graph.invocation(invocation).raw_calls().len(), 2);

    assert_eq!(
        effect_marker_evidence(
            &artifact,
            owner,
            EffectId::new(0),
            annotation_kind::<Panic>(AnnotationRole::Justification),
            AnnotationProbingFact::SourceCallsite,
        ),
        MarkerEvidenceState::Present,
        "compiler assertions use panic evidence on their effect site"
    );
    assert_eq!(
        effect_marker_evidence(
            &artifact,
            owner,
            EffectId::new(1),
            annotation_kind::<Safety>(AnnotationRole::Justification),
            AnnotationProbingFact::SourceCallsite,
        ),
        MarkerEvidenceState::Present,
        "unsafe operations use safety evidence on their effect site"
    );
    assert_eq!(
        raw_call_marker_evidence(
            &artifact,
            &graph,
            invocation,
            CallId::new(0),
            annotation_kind::<Panic>(AnnotationRole::Justification),
            AnnotationProbingFact::SourceCallsite,
        ),
        MarkerEvidenceState::VerifiedAbsent,
        "a sibling marker must not become evidence for this raw call"
    );
    assert_eq!(
        raw_call_marker_evidence(
            &artifact,
            &graph,
            invocation,
            CallId::new(1),
            annotation_kind::<Panic>(AnnotationRole::Justification),
            AnnotationProbingFact::SourceCallsite,
        ),
        MarkerEvidenceState::Present,
        "the marker remains attached to its exact raw call"
    );
    assert_eq!(
        raw_call_marker_evidence(
            &artifact,
            &graph,
            invocation,
            CallId::new(0),
            annotation_kind::<Safety>(AnnotationRole::Justification),
            AnnotationProbingFact::SourceCallsite,
        ),
        MarkerEvidenceState::Unverified(UnverifiedMarkerProbeReason::SourceUnavailable),
        "unverified evidence remains attached to its exact raw call"
    );
    assert_eq!(
        effect_marker_evidence(
            &artifact,
            owner,
            EffectId::new(99),
            annotation_kind::<Panic>(AnnotationRole::Justification),
            AnnotationProbingFact::SourceCallsite,
        ),
        MarkerEvidenceState::Unverified(UnverifiedMarkerProbeReason::NoUsableSourceSpan),
        "a missing source lookup is never reported as verified absence"
    );
}

#[test]
fn obligation_marker_evidence_uses_only_contract_carrying_raw_calls() {
    let (artifact, graph, owner) = marker_evidence_fixture();
    let invocation = graph
        .invocation_for_raw_call(owner, CallId::new(0))
        .expect("recorded source invocation");

    assert_eq!(
        obligation_marker_evidence(
            &artifact,
            &graph,
            Some(invocation),
            [CallId::new(0)],
            annotation_kind::<Panic>(AnnotationRole::Justification),
            AnnotationProbingFact::SourceCallsite,
        ),
        Some(MarkerEvidenceState::VerifiedAbsent),
        "a marker on a grouped sibling must not become source evidence"
    );
    assert_eq!(
        obligation_marker_evidence(
            &artifact,
            &graph,
            Some(invocation),
            [CallId::new(1)],
            annotation_kind::<Panic>(AnnotationRole::Justification),
            AnnotationProbingFact::SourceCallsite,
        ),
        Some(MarkerEvidenceState::Present),
        "the raw branch carrying the marker retains its evidence"
    );
    assert_eq!(
        obligation_marker_evidence(
            &artifact,
            &graph,
            Some(invocation),
            [CallId::new(0)],
            annotation_kind::<Safety>(AnnotationRole::Justification),
            AnnotationProbingFact::SourceCallsite,
        ),
        Some(MarkerEvidenceState::Unverified(
            UnverifiedMarkerProbeReason::SourceUnavailable
        ))
    );
    assert_eq!(
        obligation_marker_evidence(
            &artifact,
            &graph,
            None,
            [],
            annotation_kind::<Panic>(AnnotationRole::Justification),
            AnnotationProbingFact::SourceCallsite,
        ),
        None,
        "comment states without a source invocation carry no marker evidence"
    );
}

#[test]
fn one_exact_projection_contract_does_not_suppress_its_sibling() {
    let generic_caller = stable_function(0);
    let first_caller = exact_function(generic_caller, 1);
    let second_caller = exact_function(generic_caller, 2);
    let first_target = stable_function(3);
    let second_target = stable_function(4);
    let range = SourceRangeFact {
        file: SourceFileId::new("source-1"),
        byte_start: 10,
        byte_end: 20,
    };
    let mut first_call = call(0, target(first_target, "sample::First::run"));
    mark_safety_invocation(&mut first_call);
    first_call.source_range = Some(range.clone());
    first_call.expanded_range = Some(range.clone());
    let mut second_call = call(0, target(second_target, "sample::Second::run"));
    mark_safety_invocation(&mut second_call);
    second_call.source_range = Some(range.clone());
    second_call.expanded_range = Some(range);
    let artifact = ArtifactFacts::new(
        vec![
            body(
                first_caller,
                "sample::wrapper::<First>",
                vec![first_call],
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            body(
                second_caller,
                "sample::wrapper::<Second>",
                vec![second_call],
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            body(
                first_target,
                "sample::First::run",
                Vec::new(),
                Vec::new(),
                vec![marker(
                    0,
                    annotation_kind::<Safety>(AnnotationRole::Contract),
                    AnnotationTargetFact::Function(first_target),
                )],
                Vec::new(),
            ),
            body(
                second_target,
                "sample::Second::run",
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
        ],
        vec![SourceFileFact {
            id: SourceFileId::new("source-1"),
            filename: String::from("src/lib.rs"),
            content_hash: String::from("sha256:0123456789abcdef"),
            byte_len: 100,
        }],
    )
    .expect("valid exact projection fixture");
    let graph = InvocationGraph::from_artifact(&artifact).expect("invocation graph");
    let annotations = AnnotationIndex::from_artifact(&artifact, &graph).expect("annotations");
    let first = graph
        .invocation_for_raw_call(first_caller, CallId::new(0))
        .expect("first invocation");
    let second = graph
        .invocation_for_raw_call(second_caller, CallId::new(0))
        .expect("second invocation");
    let config = crate::config::test_config();
    let namespaces = artifact.definition_namespace_index();
    let safety = probe_concrete_effect_for::<Safety>(
        &artifact,
        &graph,
        &annotations,
        &namespaces,
        config.effect("safety"),
    )
    .expect("safety effect");

    assert!(invocation_source_has_contract(
        &graph,
        &annotations,
        &safety.invocation_sources(first)[0],
        &ReportEffect::Safety.key(),
    ));
    assert!(!invocation_source_has_contract(
        &graph,
        &annotations,
        &safety.invocation_sources(second)[0],
        &ReportEffect::Safety.key(),
    ));
}

#[test]
fn grouped_panic_sink_uses_its_matched_declaration_branch() {
    let root = stable_function(10);
    let contracted = stable_function(11);
    let sink = stable_function(12);
    let mut sink_call = indirect_call(
        1,
        0,
        bodyless_declaration(sink, "sink::panic", FunctionContractsFact::default()),
    );
    mark_panic_invocation(&mut sink_call);
    sink_call.call_site = CallSiteId::new(0);
    let artifact = ArtifactFacts::new(
        vec![
            body(
                root,
                "sample::root",
                vec![call(0, target(contracted, "sample::contracted")), sink_call],
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            body(
                contracted,
                "sample::contracted",
                Vec::new(),
                Vec::new(),
                vec![marker(
                    0,
                    annotation_kind::<Panic>(AnnotationRole::Contract),
                    AnnotationTargetFact::Function(contracted),
                )],
                Vec::new(),
            ),
        ],
        Vec::new(),
    )
    .expect("grouped panic sink artifact");
    let config = crate::config::test_config();

    let reports = trace_workspace(
        &artifact,
        root.def_path_hash.stable_crate_id(),
        &ArtifactAnalysisGraph::default(),
        &[InterpretationRoot {
            function: root,
            path: String::from("sample::root"),
            kind: ReportRootKind::Concrete,
        }],
        &config,
    )
    .expect("effect report");
    let sinks = reports[0]
        .findings
        .iter()
        .filter(|finding| {
            finding.effect.justification == "PANIC"
                && matches!(finding.kind, InterpretedFindingKind::Invocation { .. })
        })
        .collect::<Vec<_>>();

    assert_eq!(sinks.len(), 1);
    assert_eq!(
        sinks[0].callee.as_ref().map(|callee| callee.path.as_str()),
        Some("sink::panic")
    );
}

#[test]
fn grouped_unsafe_call_uses_its_actual_unsafe_branch() {
    let root = stable_function(20);
    let contracted_safe = stable_function(21);
    let mut unsafe_pointer = call(
        1,
        CallTargetFact::OpaqueBoundary {
            description: String::from("unresolved unsafe function pointer"),
            target: None,
        },
    );
    unsafe_pointer.call_site = CallSiteId::new(0);
    unsafe_pointer.kind = CallKindFact::IndirectCall;
    unsafe_pointer.indirect_kind = Some(IndirectCallKindFact::FunctionPointer);
    mark_safety_invocation(&mut unsafe_pointer);
    let artifact = ArtifactFacts::new(
        vec![
            body(
                root,
                "sample::root",
                vec![
                    call(0, target(contracted_safe, "sample::contracted_safe")),
                    unsafe_pointer,
                ],
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            body(
                contracted_safe,
                "sample::contracted_safe",
                Vec::new(),
                Vec::new(),
                vec![marker(
                    0,
                    annotation_kind::<Safety>(AnnotationRole::Contract),
                    AnnotationTargetFact::Function(contracted_safe),
                )],
                Vec::new(),
            ),
        ],
        Vec::new(),
    )
    .expect("grouped unsafe call artifact");
    let config = crate::config::test_from_manifest_str(
        "[safety.coverage]\nunresolved-call-target = \"warn\"",
    )
    .expect("unresolved safety coverage configuration");

    let reports = trace_workspace(
        &artifact,
        root.def_path_hash.stable_crate_id(),
        &ArtifactAnalysisGraph::default(),
        &[InterpretationRoot {
            function: root,
            path: String::from("sample::root"),
            kind: ReportRootKind::Concrete,
        }],
        &config,
    )
    .expect("effect report");
    let unsafe_calls = reports[0]
        .findings
        .iter()
        .filter(|finding| {
            finding.effect.justification == "SAFETY"
                && matches!(finding.kind, InterpretedFindingKind::Invocation { .. })
        })
        .collect::<Vec<_>>();

    assert_eq!(unsafe_calls.len(), 1);
    assert_eq!(
        unsafe_calls[0]
            .callee
            .as_ref()
            .map(|target| target.path.as_str()),
        Some("opaque function pointer")
    );
    assert_eq!(
        reports[0]
            .findings
            .iter()
            .filter(|finding| matches!(
                finding.kind,
                InterpretedFindingKind::UnresolvedCallTarget { .. }
            ) && finding.effect.key == ReportEffect::Safety.key())
            .count(),
        1,
        "the unsafe signature is a local SafetyEffect source, but it does not make the unknown implementation complete"
    );
}

#[test]
fn grouped_panic_marker_ambiguity_uses_the_actual_sink_branch() {
    let root = stable_function(30);
    let nonsink = stable_function(31);
    let sink = stable_function(32);
    let mut sink_call = indirect_call(
        1,
        0,
        bodyless_declaration(sink, "sink::panic", FunctionContractsFact::default()),
    );
    mark_panic_invocation(&mut sink_call);
    sink_call.call_site = CallSiteId::new(0);
    let compiler_assert = EffectFact {
        id: EffectId::new(0),
        effect: EffectKey::new("panic"),
        effect_group: None,
        source_range: None,
        expanded_range: None,
        macro_expansions: vec![
            MacroExpansionFact {
                macro_def: stable_function(33).def_path_hash,
                display_path: String::from("sample::outer_assert"),
                source_range: None,
            },
            MacroExpansionFact {
                macro_def: stable_function(34).def_path_hash,
                display_path: String::from("sample::inner_assert"),
                source_range: None,
            },
        ],
        kind: EffectKind::new("bounds-check"),
    };
    let artifact = ArtifactFacts::new(
        vec![
            body(
                root,
                "sample::root",
                vec![call(0, target(nonsink, "sample::nonsink")), sink_call],
                vec![compiler_assert],
                vec![
                    shared_justification_marker(
                        0,
                        "shared-panic-marker",
                        annotation_kind::<Panic>(AnnotationRole::Justification),
                        AnnotationTargetFact::Call(CallId::new(1)),
                    ),
                    shared_justification_marker(
                        1,
                        "shared-panic-marker",
                        annotation_kind::<Panic>(AnnotationRole::Justification),
                        AnnotationTargetFact::Effect(EffectId::new(0)),
                    ),
                ],
                Vec::new(),
            ),
            body(
                nonsink,
                "sample::nonsink",
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
        ],
        Vec::new(),
    )
    .expect("grouped panic marker artifact");
    let config = crate::config::test_config();

    let reports = trace_workspace(
        &artifact,
        root.def_path_hash.stable_crate_id(),
        &ArtifactAnalysisGraph::default(),
        &[InterpretationRoot {
            function: root,
            path: String::from("sample::root"),
            kind: ReportRootKind::Concrete,
        }],
        &config,
    )
    .expect("effect report");
    let ambiguity = reports[0]
        .findings
        .iter()
        .find(|finding| matches!(finding.kind, InterpretedFindingKind::AmbiguousMarker { .. }))
        .unwrap_or_else(|| panic!("ambiguous panic marker: {:#?}", reports[0].findings));
    assert!(matches!(
        ambiguity.kind,
        InterpretedFindingKind::AmbiguousMarker { effect_count: 2 }
    ));
    let source = ambiguity.trace.steps.last().expect("source trace step");

    assert_eq!(source.call, CallId::new(1));
    assert_eq!(source.target_path.as_deref(), Some("sink::panic"));
}

#[test]
fn grouped_safety_marker_uses_actual_branch_group_and_source_trace() {
    let root = stable_function(40);
    let safe = stable_function(41);
    let unsafe_target = stable_function(42);
    let mut unsafe_call = call(1, target(unsafe_target, "sample::unsafe_target"));
    unsafe_call.call_site = CallSiteId::new(0);
    unsafe_call.effect_group = Some(EffectGroupId::new(1));
    mark_safety_invocation(&mut unsafe_call);
    let artifact = ArtifactFacts::new(
        vec![
            body(
                root,
                "sample::root",
                vec![call(0, target(safe, "sample::safe")), unsafe_call],
                vec![
                    unsafe_operation_with_provenance(0, 1, 43),
                    unsafe_operation_with_provenance(1, 2, 45),
                ],
                vec![
                    shared_justification_marker(
                        0,
                        "shared-safety-marker",
                        annotation_kind::<Safety>(AnnotationRole::Justification),
                        AnnotationTargetFact::Call(CallId::new(1)),
                    ),
                    shared_justification_marker(
                        1,
                        "shared-safety-marker",
                        annotation_kind::<Safety>(AnnotationRole::Justification),
                        AnnotationTargetFact::Effect(EffectId::new(0)),
                    ),
                    shared_justification_marker(
                        2,
                        "shared-safety-marker",
                        annotation_kind::<Safety>(AnnotationRole::Justification),
                        AnnotationTargetFact::Effect(EffectId::new(1)),
                    ),
                ],
                Vec::new(),
            ),
            body(
                safe,
                "sample::safe",
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            body(
                unsafe_target,
                "sample::unsafe_target",
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
        ],
        Vec::new(),
    )
    .expect("grouped safety marker artifact");

    let reports = trace_workspace(
        &artifact,
        root.def_path_hash.stable_crate_id(),
        &ArtifactAnalysisGraph::default(),
        &[InterpretationRoot {
            function: root,
            path: String::from("sample::root"),
            kind: ReportRootKind::Concrete,
        }],
        &crate::config::test_config(),
    )
    .expect("effect report");
    let ambiguity = reports[0]
        .findings
        .iter()
        .find(|finding| matches!(finding.kind, InterpretedFindingKind::AmbiguousMarker { .. }))
        .unwrap_or_else(|| panic!("ambiguous safety marker: {:#?}", reports[0].findings));
    assert!(matches!(
        ambiguity.kind,
        InterpretedFindingKind::AmbiguousMarker { effect_count: 2 }
    ));
    let source = ambiguity.trace.steps.last().expect("source trace step");

    assert_eq!(source.call, CallId::new(1));
    assert_eq!(source.target_path.as_deref(), Some("sample::unsafe_target"));
}

fn grouped_comment_claim_artifact(root: FunctionId, obligation: FunctionId) -> ArtifactFacts {
    let mut first_call = call(0, target(obligation, "sample::safe_obligation"));
    first_call.effect_group = Some(EffectGroupId::new(1));
    let mut second_call = call(1, target(obligation, "sample::safe_obligation"));
    second_call.effect_group = Some(EffectGroupId::new(1));
    let mut first_marker = shared_justification_marker(
        0,
        "shared-contract-marker",
        annotation_kind::<Safety>(AnnotationRole::Justification),
        AnnotationTargetFact::Call(CallId::new(0)),
    );
    first_marker.satisfactions[0].requirement = Some(String::from("initialized"));
    let mut second_marker = shared_justification_marker(
        1,
        "shared-contract-marker",
        annotation_kind::<Safety>(AnnotationRole::Justification),
        AnnotationTargetFact::Call(CallId::new(1)),
    );
    second_marker.satisfactions[0].requirement = Some(String::from("initialized"));
    let mut contract = marker(
        2,
        annotation_kind::<Safety>(AnnotationRole::Contract),
        AnnotationTargetFact::Function(obligation),
    );
    contract.requirements = vec![
        crate::artifact::ContractRequirementFact {
            name: String::from("initialized"),
            condition: String::from("state must be initialized"),
            structural_path: vec![0],
            source_range: None,
        },
        crate::artifact::ContractRequirementFact {
            name: String::from("exclusive"),
            condition: String::from("access must be exclusive"),
            structural_path: vec![1],
            source_range: None,
        },
    ];
    ArtifactFacts::new(
        vec![
            body(
                root,
                "sample::root",
                vec![first_call, second_call],
                Vec::new(),
                vec![first_marker, second_marker],
                Vec::new(),
            ),
            body(
                obligation,
                "sample::safe_obligation",
                Vec::new(),
                Vec::new(),
                vec![contract],
                Vec::new(),
            ),
        ],
        Vec::new(),
    )
    .expect("grouped safety contract artifact")
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one fixture exercises grouped marker paths"
)]
fn grouped_comment_marker_claims_each_relevant_contract_branch() {
    let root = stable_function(47);
    let artifact = grouped_comment_claim_artifact(root, stable_function(48));

    let graph = InvocationGraph::from_artifact(&artifact).expect("invocation graph");
    let annotations = AnnotationIndex::from_artifact(&artifact, &graph).expect("annotations");
    let config = crate::config::test_config();
    let namespaces = artifact.definition_namespace_index();
    let panic = probe_concrete_effect_for::<Panic>(
        &artifact,
        &graph,
        &annotations,
        &namespaces,
        config.effect("panic"),
    )
    .expect("panic effect");
    let safety = probe_concrete_effect_for::<Safety>(
        &artifact,
        &graph,
        &annotations,
        &namespaces,
        config.effect("safety"),
    )
    .expect("safety effect");
    let comments = super::ObligationTracker::probe(
        &graph,
        &annotations,
        config.analysis.effect_doc_matching,
        [
            super::ObligationEffectPolicy::new(
                super::ReportEffect::Panic.key(),
                panic.trusted_functions(),
                panic.ignored_invocations(),
            ),
            super::ObligationEffectPolicy::new(
                super::ReportEffect::Safety.key(),
                safety.trusted_functions(),
                safety.ignored_invocations(),
            ),
        ],
    );
    let panic_key = super::ReportEffect::Panic.key();
    let safety_key = super::ReportEffect::Safety.key();
    let concrete_effects = std::collections::BTreeMap::from([
        (panic_key.clone(), panic),
        (safety_key.clone(), safety),
    ]);
    let tracked_effects = concrete_effects
        .iter()
        .map(|(effect, concrete)| {
            (
                effect.clone(),
                super::TrackedEffect::new(concrete, &comments, effect.clone()),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let obligation_graph = graph.obligation_graph();
    let engine = EffectEngine::new(&obligation_graph);
    let traces = tracked_effects
        .iter()
        .map(|(effect, tracked)| (effect.clone(), engine.trace(tracked)))
        .collect::<std::collections::BTreeMap<_, super::ConcreteTrace>>();
    let tracked_safety = tracked_effects.get(&safety_key).expect("tracked safety");
    let safety_trace = traces.get(&safety_key).expect("safety trace");
    let uses = tracked_safety.obligation_marker_uses(safety_trace);
    assert_eq!(
        comments.contract_count(&super::ReportEffect::Safety.key()),
        1
    );
    assert_eq!(uses.len(), 1, "marker uses: {uses:#?}");
    assert_eq!(
        uses[0].source_calls().collect::<Vec<_>>(),
        vec![CallId::new(0), CallId::new(1)],
    );
    assert_eq!(
        super::obligation_effect_groups(
            &graph,
            concrete_effects.get(&safety_key),
            &safety_key,
            uses[0].source_invocation(),
            uses[0].source_calls(),
        ),
        vec![
            super::SourceEffectGroup::Invocation(uses[0].source_invocation(), CallId::new(0),),
            super::SourceEffectGroup::Invocation(uses[0].source_invocation(), CallId::new(1),),
        ],
    );
    let claims = super::collect_marker_claims(
        &artifact,
        &graph,
        &concrete_effects,
        &traces,
        &tracked_effects,
    );
    assert_eq!(
        claims.values().next().map(std::collections::BTreeMap::len),
        Some(2),
        "claims: {claims:#?}",
    );
    let root_function = graph.function(root).expect("root function");
    let ambiguities = super::marker_ambiguities(
        &artifact,
        &graph,
        &annotations,
        &concrete_effects,
        &traces,
        &tracked_effects,
        &claims,
        &[EffectMetadata::of::<Safety>()],
        root_function,
    );

    assert!(matches!(
        ambiguities.as_slice(),
        [InterpretedFinding {
            kind: InterpretedFindingKind::AmbiguousMarker { effect_count: 2 },
            ..
        }]
    ));
}

fn trusted_safety_marker_artifact(root: FunctionId, trusted: FunctionId) -> ArtifactFacts {
    let mut trusted_body = body(
        trusted,
        "trusted::api",
        Vec::new(),
        vec![
            unsafe_operation_with_provenance(0, 1, 52),
            unsafe_operation_with_provenance(1, 2, 54),
        ],
        vec![
            shared_justification_marker(
                0,
                "trusted-shared-safety-marker",
                annotation_kind::<Safety>(AnnotationRole::Justification),
                AnnotationTargetFact::Effect(EffectId::new(0)),
            ),
            shared_justification_marker(
                1,
                "trusted-shared-safety-marker",
                annotation_kind::<Safety>(AnnotationRole::Justification),
                AnnotationTargetFact::Effect(EffectId::new(1)),
            ),
            marker(
                2,
                annotation_kind::<Safety>(AnnotationRole::Contract),
                AnnotationTargetFact::Function(trusted),
            ),
        ],
        Vec::new(),
    );
    trusted_body
        .attributes
        .namespace_candidates
        .push(String::from("trusted"));
    ArtifactFacts::new(
        vec![
            body(
                root,
                "sample::root",
                vec![call(0, target(trusted, "trusted::api"))],
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            trusted_body,
        ],
        Vec::new(),
    )
    .expect("trusted safety marker artifact")
}

#[test]
fn trusted_safety_boundary_hides_internal_marker_ambiguity_but_exports_its_contract() {
    let root = stable_function(50);
    let trusted = stable_function(51);
    let artifact = trusted_safety_marker_artifact(root, trusted);
    let roots = [InterpretationRoot {
        function: root,
        path: String::from("sample::root"),
        kind: ReportRootKind::Concrete,
    }];
    let untrusted_config =
        crate::config::test_from_manifest_str("[analysis]\nmarker-probing = \"source-callsite\"")
            .expect("source-callsite marker configuration");
    let untrusted_reports = trace_workspace(
        &artifact,
        root.def_path_hash.stable_crate_id(),
        &ArtifactAnalysisGraph::default(),
        &roots,
        &untrusted_config,
    )
    .expect("untrusted effect report");
    assert!(untrusted_reports[0].findings.iter().any(|finding| {
        matches!(
            finding.kind,
            InterpretedFindingKind::AmbiguousMarker { effect_count: 2 }
        )
    }));

    let config = crate::config::test_from_manifest_str(
        r#"
                [analysis]
                marker-probing = "source-callsite"

                [safety]
                trusted-boundary-namespaces = ["trusted"]
            "#,
    )
    .expect("trusted safety boundary configuration");

    let reports = trace_workspace(
        &artifact,
        root.def_path_hash.stable_crate_id(),
        &ArtifactAnalysisGraph::default(),
        &roots,
        &config,
    )
    .expect("effect report");
    let findings = &reports[0].findings;

    assert!(
        findings
            .iter()
            .all(|finding| !matches!(finding.kind, InterpretedFindingKind::AmbiguousMarker { .. })),
        "trusted implementation details must not project marker ambiguity: {findings:#?}",
    );
    let surface = findings
        .iter()
        .filter(|finding| {
            finding.effect.justification == "SAFETY"
                && matches!(finding.kind, InterpretedFindingKind::DocumentedObligation)
                && finding
                    .callee
                    .as_ref()
                    .is_some_and(|target| target.path == "trusted::api")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        surface.len(),
        1,
        "the trusted API's own # Safety contract must remain visible: {findings:#?}",
    );
}

#[test]
fn managed_callback_missing_body_crosses_trusted_boundary() {
    let root = function_in_crate(1, 1);
    let callback = function_in_crate(1, 2);
    let consumer = function_in_crate(2, 1);
    let declaration = function_in_crate(2, 2);
    let mut callback_call = call(0, target(callback, "app::callback"));
    let CallTargetFact::Function(surface) = target(declaration, "trusted::Callback::call") else {
        unreachable!();
    };
    callback_call.declaration_target = Some(surface);
    let local = ArtifactFacts::new(
        vec![body(
            root,
            "app::root",
            vec![call(0, target(consumer, "trusted::consume"))],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )],
        Vec::new(),
    )
    .expect("local callback fixture");
    let dependencies = loaded_dependency(
        2,
        ArtifactFacts::new(
            vec![body(
                consumer,
                "trusted::consume",
                vec![callback_call],
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )],
            Vec::new(),
        )
        .expect("trusted consumer fixture"),
    );
    let reports = trace_workspace(
        &local,
        1,
        &dependencies,
        &[InterpretationRoot {
            function: root,
            path: String::from("app::root"),
            kind: ReportRootKind::Concrete,
        }],
        &trusted_declaration_config(),
    )
    .expect("callback missing-body report");
    assert_eq!(
        missing_body_targets(completeness_for(&reports[0], ReportEffect::Panic)),
        [callback]
    );
    assert_eq!(
        missing_body_targets(completeness_for(&reports[0], ReportEffect::Safety)),
        [callback]
    );
}

#[test]
fn managed_missing_bodies_are_report_root_scoped() {
    let local_stable_crate_id = 1;
    let dependency_stable_crate_id = 2;
    let root = function_in_crate(local_stable_crate_id, 1);
    let unrelated_root = function_in_crate(local_stable_crate_id, 2);
    let local_missing = function_in_crate(local_stable_crate_id, 3);
    let dependency_missing = function_in_crate(dependency_stable_crate_id, 1);
    let unmanaged_missing = function_in_crate(3, 1);
    let mut local_call = call(0, target(local_missing, "app::local_missing"));
    local_call.call_site = CallSiteId::new(0);
    let mut dependency_call = call(1, target(dependency_missing, "dependency::missing"));
    dependency_call.call_site = CallSiteId::new(1);
    let mut unmanaged_call = call(2, target(unmanaged_missing, "core::unmanaged"));
    unmanaged_call.call_site = CallSiteId::new(2);
    let local = ArtifactFacts::new(
        vec![
            body(
                root,
                "app::root",
                vec![local_call, dependency_call, unmanaged_call],
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            body(
                unrelated_root,
                "app::unrelated_root",
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
        ],
        Vec::new(),
    )
    .expect("managed missing-body fixture");
    let dependencies = loaded_dependency(
        dependency_stable_crate_id,
        ArtifactFacts::new(Vec::new(), Vec::new()).expect("empty dependency facts"),
    );

    let reports = trace_workspace(
        &local,
        local_stable_crate_id,
        &dependencies,
        &[
            InterpretationRoot {
                function: root,
                path: String::from("app::root"),
                kind: ReportRootKind::Concrete,
            },
            InterpretationRoot {
                function: unrelated_root,
                path: String::from("app::unrelated_root"),
                kind: ReportRootKind::Concrete,
            },
        ],
        &crate::config::test_config(),
    )
    .expect("effect report");

    let root_report = &reports[0];
    assert_eq!(
        missing_body_targets(completeness_for(root_report, ReportEffect::Panic)),
        [local_missing, dependency_missing]
    );
    assert_eq!(
        missing_body_targets(completeness_for(root_report, ReportEffect::Safety)),
        [local_missing, dependency_missing]
    );
    for reason in completeness_for(root_report, ReportEffect::Panic)
        .reasons
        .iter()
        .chain(&completeness_for(root_report, ReportEffect::Safety).reasons)
    {
        let IncompleteReason::MissingBody {
            function, trace, ..
        } = reason
        else {
            continue;
        };
        assert_eq!(
            trace.steps.last().and_then(|step| step.target),
            Some(*function)
        );
    }
    assert!(completeness_for(&reports[1], ReportEffect::Panic).complete);
    assert!(completeness_for(&reports[1], ReportEffect::Safety).complete);
}

#[test]
fn consumer_overlay_is_complete_for_panic_but_not_definition_site_safety() {
    let local_stable_crate_id = 1;
    let dependency_stable_crate_id = 2;
    let root = function_in_crate(local_stable_crate_id, 1);
    let overlay_definition = function_in_crate(dependency_stable_crate_id, 1);
    let overlay = exact_function(overlay_definition, 10);
    let defining_generic = function_in_crate(dependency_stable_crate_id, 2);
    let exact_with_fallback = exact_function(defining_generic, 11);
    let mut overlay_body = body(
        overlay,
        "dependency::overlay::<App>",
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    overlay_body.provenance = FunctionFactProvenance::ConsumerInstantiation {
        consumer_stable_crate_id: local_stable_crate_id,
    };
    let local = ArtifactFacts::new(
        vec![
            body(
                root,
                "app::root",
                vec![
                    call(0, target(overlay, "dependency::overlay::<App>")),
                    call(1, target(exact_with_fallback, "dependency::generic::<App>")),
                ],
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            overlay_body,
        ],
        Vec::new(),
    )
    .expect("consumer overlay fixture");
    let dependencies = loaded_dependency(
        dependency_stable_crate_id,
        ArtifactFacts::new(
            vec![body(
                defining_generic,
                "dependency::generic",
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )],
            Vec::new(),
        )
        .expect("defining dependency facts"),
    );

    let reports = trace_workspace(
        &local,
        local_stable_crate_id,
        &dependencies,
        &[InterpretationRoot {
            function: root,
            path: String::from("app::root"),
            kind: ReportRootKind::Concrete,
        }],
        &crate::config::test_config(),
    )
    .expect("effect report");

    assert!(completeness_for(&reports[0], ReportEffect::Panic).complete);
    assert_eq!(
        missing_body_targets(completeness_for(&reports[0], ReportEffect::Safety)),
        [overlay]
    );
}

#[test]
fn registered_passes_determine_missing_body_completeness_for_new_effects() {
    let root = function_in_crate(1, 1);
    let definition = function_in_crate(2, 1);
    let overlay = exact_function(definition, 10);
    let mut overlay_body = body(
        overlay,
        "dependency::overlay::<App>",
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    overlay_body.provenance = FunctionFactProvenance::ConsumerInstantiation {
        consumer_stable_crate_id: 1,
    };
    let local = ArtifactFacts::new(
        vec![
            body(
                root,
                "app::root",
                vec![call(0, target(overlay, "dependency::overlay::<App>"))],
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            overlay_body,
        ],
        Vec::new(),
    )
    .expect("consumer overlay fixture");
    let dependencies = loaded_dependency(
        2,
        ArtifactFacts::new(Vec::new(), Vec::new()).expect("empty dependency facts"),
    );
    let config = crate::config::test_config();
    let effects = [
        effect::<Allocation>(config.effect("panic")),
        effect::<SourceAllocation>(config.effect("panic")),
    ];
    let reports = super::trace_selected_workspace(
        &local,
        1,
        &dependencies,
        &std::collections::BTreeMap::new(),
        &[InterpretationRoot {
            function: root,
            path: String::from("app::root"),
            kind: ReportRootKind::Concrete,
        }],
        &config,
        &effects,
    )
    .expect("effect report");

    assert!(reports[0].completeness.effects[&EffectKey::new("allocation")].complete);
    assert_eq!(
        missing_body_targets(
            &reports[0].completeness.effects[&EffectKey::new("source-allocation")]
        ),
        [overlay]
    );
}

#[test]
fn trusted_boundary_filters_each_concrete_target_in_its_own_domain() {
    let local_stable_crate_id = 1;
    let dependency_stable_crate_id = 2;
    let root = function_in_crate(local_stable_crate_id, 1);
    let trusted_missing = function_in_crate(dependency_stable_crate_id, 1);
    let ignored_contracted_missing = function_in_crate(dependency_stable_crate_id, 2);
    let present = function_in_crate(dependency_stable_crate_id, 3);
    let mut contracted_target =
        match target(ignored_contracted_missing, "ignored::contracted_missing") {
            CallTargetFact::Function(target) => target,
            CallTargetFact::OpaqueBoundary { .. } => unreachable!("concrete target helper"),
        };
    contracted_target.contracts = effect_contracts(Some(whole_contract()), Some(whole_contract()));
    let local = ArtifactFacts::new(
        vec![body(
            root,
            "app::root",
            vec![
                call(0, target(trusted_missing, "visible::trusted_missing")),
                call(1, CallTargetFact::Function(contracted_target)),
                call(2, target(present, "dependency::present")),
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )],
        Vec::new(),
    )
    .expect("multi-target missing-body fixture");
    let dependencies = loaded_dependency(
        dependency_stable_crate_id,
        ArtifactFacts::new(
            vec![body(
                present,
                "dependency::present",
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )],
            Vec::new(),
        )
        .expect("dependency with one available target"),
    );
    let config = crate::config::test_from_manifest_str(
        r#"
                [panic]
                trusted-boundary-namespaces = ["visible::**"]
                ignored-namespaces = ["ignored::**"]
                [safety]
                ignored-namespaces = ["ignored::**"]
            "#,
    )
    .expect("domain-local trusted-boundary config");

    let reports = trace_workspace(
        &local,
        local_stable_crate_id,
        &dependencies,
        &[InterpretationRoot {
            function: root,
            path: String::from("app::root"),
            kind: ReportRootKind::Concrete,
        }],
        &config,
    )
    .expect("effect report");

    assert_eq!(
        missing_body_targets(completeness_for(&reports[0], ReportEffect::Panic)),
        [ignored_contracted_missing],
        "ignored namespaces and ordinary contracts are not completeness boundaries"
    );
    assert_eq!(
        missing_body_targets(completeness_for(&reports[0], ReportEffect::Safety)),
        [trusted_missing, ignored_contracted_missing]
    );
}

#[test]
fn report_root_does_not_owe_or_duplicate_effective_trait_contracts() {
    let implementation = stable_function(0);
    let declaration = stable_function(1);
    let mut implementation_body = body(
        implementation,
        "sample::Impl::run",
        Vec::new(),
        vec![EffectFact {
            id: EffectId::new(0),
            effect: EffectKey::new("panic"),
            effect_group: None,
            source_range: None,
            expanded_range: None,
            macro_expansions: Vec::new(),
            kind: EffectKind::new("bounds-check"),
        }],
        Vec::new(),
        Vec::new(),
    );
    implementation_body.attributes.is_unsafe = true;
    implementation_body.contract_declaration = Some(FunctionTargetFact {
        function: declaration,
        display_path: String::from("sample::Trait::run"),
        attributes: attributes("sample::Trait::run"),
        contracts: FunctionContractsFact::default(),
    });
    let artifact = ArtifactFacts::new(
        vec![
            implementation_body,
            body(
                declaration,
                "sample::Trait::run",
                Vec::new(),
                Vec::new(),
                vec![
                    marker(
                        0,
                        annotation_kind::<Panic>(AnnotationRole::Contract),
                        AnnotationTargetFact::Function(declaration),
                    ),
                    marker(
                        1,
                        annotation_kind::<Safety>(AnnotationRole::Contract),
                        AnnotationTargetFact::Function(declaration),
                    ),
                ],
                Vec::new(),
            ),
        ],
        Vec::new(),
    )
    .expect("effective trait contract artifact");
    let graph = InvocationGraph::from_artifact(&artifact).expect("invocation graph");
    let annotations = AnnotationIndex::from_artifact(&artifact, &graph).expect("annotations");
    let implementation_graph = graph.function(implementation).expect("implementation");
    assert_eq!(
        annotations
            .effective_contract(&graph, implementation_graph, &ReportEffect::Panic.key())
            .expect("effective panic contract")
            .owner(),
        declaration,
    );
    assert_eq!(
        annotations
            .effective_contract(&graph, implementation_graph, &ReportEffect::Safety.key())
            .expect("effective safety contract")
            .owner(),
        declaration,
    );
    let mut config = crate::config::test_config();
    config.analysis.marker_probing = MarkerProbing::SourceCallsite;

    let reports = trace_workspace(
        &artifact,
        implementation.def_path_hash.stable_crate_id(),
        &ArtifactAnalysisGraph::default(),
        &[InterpretationRoot {
            function: implementation,
            path: String::from("sample::Impl::run"),
            kind: ReportRootKind::Concrete,
        }],
        &config,
    )
    .expect("effect report");

    assert!(
        reports[0].findings.is_empty(),
        "unexpected findings: {:#?}",
        reports[0].findings,
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one declaration-coverage matrix compares mixed contract, trust, ignore, sink, and duplicate raw-edge cases"
)]
fn every_desugared_declaration_requires_contract_or_boundary_coverage() {
    let cases = [
        (
            20,
            "other::Iterator::next",
            true,
            "other::IntoIterator::into_iter",
            1,
        ),
        (
            30,
            "other::Iterator::next",
            true,
            "trusted::IntoIterator::into_iter",
            0,
        ),
        (
            40,
            "other::Iterator::next",
            true,
            "ignored::IntoIterator::into_iter",
            0,
        ),
        (
            50,
            "other::Iterator::next",
            true,
            "sink::IntoIterator::into_iter",
            1,
        ),
        // A representative ignored edge must not hide its uncovered
        // sibling merely because rustc grouped them at one source site.
        (60, "ignored::Iterator::next", false, "other::uncovered", 1),
        // Each independently uncovered declaration needs its own action;
        // fixing one must not reveal a hidden sibling only on the next run.
        (70, "other::first", false, "other::second", 2),
    ];
    let mut bodies = cases
        .iter()
        .map(|(base, first_path, first_has_contract, second_path, _)| {
            desugared_declaration_body(*base, first_path, *first_has_contract, second_path)
        })
        .collect::<Vec<_>>();
    let repeated_body = bodies
        .iter_mut()
        .find(|body| body.function == stable_function(70))
        .expect("two-uncovered-declaration body");
    let mut repeated_first = repeated_body.calls[0].clone();
    repeated_first.id = CallId::new(2);
    repeated_body.calls.push(repeated_first);
    let artifact = ArtifactFacts::new(bodies, Vec::new()).expect("desugared declaration artifact");
    let config = crate::config::test_from_manifest_str(
        r#"
                [panic]
                trusted-boundary-namespaces = ["trusted::**"]
                ignored-namespaces = ["ignored::**"]
                [panic.coverage]
                unresolved-call-target = "warn"
            "#,
    )
    .expect("declaration coverage configuration");
    let roots = cases
        .iter()
        .map(|(base, _, _, _, _)| InterpretationRoot {
            function: stable_function(*base),
            path: format!("sample::root_{base}"),
            kind: ReportRootKind::Concrete,
        })
        .collect::<Vec<_>>();

    let reports = trace_workspace(
        &artifact,
        roots[0].function.def_path_hash.stable_crate_id(),
        &ArtifactAnalysisGraph::default(),
        &roots,
        &config,
    )
    .expect("effect report");

    for (base, _, _, second_path, expected) in cases {
        assert_eq!(
            unresolved_panic_count(&reports, stable_function(base)),
            expected,
            "unexpected declaration coverage for {second_path}"
        );
    }

    let uncovered = reports
        .iter()
        .find(|report| report.root.function == stable_function(20))
        .expect("partially covered root report")
        .findings
        .iter()
        .find(|finding| {
            matches!(
                finding.kind,
                InterpretedFindingKind::UnresolvedCallTarget { .. }
            )
        })
        .expect("uncovered second declaration");
    assert_eq!(
        uncovered.callee.as_ref().map(|callee| callee.path.as_str()),
        Some("other::IntoIterator::into_iter")
    );
    assert_eq!(
        uncovered
            .trace
            .steps
            .last()
            .and_then(|step| step.target_path.as_deref()),
        Some("other::IntoIterator::into_iter")
    );
}

#[test]
fn covered_declaration_does_not_hide_targetless_unknown_sibling() {
    let root = stable_function(70);
    let declaration = stable_function(71);
    let contracts = effect_contracts(Some(whole_contract()), Some(whole_contract()));
    let artifact = ArtifactFacts::new(
        vec![body(
            root,
            "sample::root_70",
            vec![
                indirect_call(
                    0,
                    0,
                    bodyless_declaration(declaration, "other::covered", contracts),
                ),
                targetless_call(1, 0, "unresolved targetless sibling"),
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )],
        Vec::new(),
    )
    .expect("covered declaration with targetless sibling artifact");
    let config = crate::config::test_from_manifest_str(
        r#"
                [panic.coverage]
                unresolved-call-target = "warn"
                [safety.coverage]
                unresolved-call-target = "warn"
            "#,
    )
    .expect("unresolved coverage configuration");

    let reports = trace_workspace(
        &artifact,
        root.def_path_hash.stable_crate_id(),
        &ArtifactAnalysisGraph::default(),
        &[InterpretationRoot {
            function: root,
            path: String::from("sample::root_70"),
            kind: ReportRootKind::Concrete,
        }],
        &config,
    )
    .expect("effect report");
    let unresolved = reports[0]
        .findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.kind,
                InterpretedFindingKind::UnresolvedCallTarget { .. }
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(unresolved.len(), 2, "one finding per effect domain");
    for finding in unresolved {
        assert_eq!(finding.callee, None);
        assert_eq!(
            finding.trace.steps.last().map(|step| step.call),
            Some(CallId::new(1))
        );
        assert_eq!(
            finding
                .trace
                .steps
                .last()
                .and_then(|step| step.target_path.as_deref()),
            Some("indirect call through a function pointer")
        );
    }
}

#[test]
fn independent_declaration_surface_propagates_contracts_and_covers_targetless_call() {
    let root = stable_function(80);
    let declaration = stable_function(81);
    let mut declaration_attributes = attributes("sample::Callable::call");
    declaration_attributes.has_rust_body = false;
    let mut invocation = targetless_call(0, 0, "unresolved dynamic dispatch");
    invocation.declaration_target = Some(FunctionTargetFact {
        function: declaration,
        display_path: String::from("sample::Callable::call"),
        attributes: declaration_attributes,
        contracts: effect_contracts(Some(whole_contract()), Some(whole_contract())),
    });
    let artifact = ArtifactFacts::new(
        vec![body(
            root,
            "sample::root_80",
            vec![invocation],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )],
        Vec::new(),
    )
    .expect("targetless call with independent declaration surface");
    let config = crate::config::test_from_manifest_str(
        r#"
                [panic.coverage]
                unresolved-call-target = "warn"
                [safety.coverage]
                unresolved-call-target = "warn"
            "#,
    )
    .expect("unresolved coverage configuration");

    let reports = trace_workspace(
        &artifact,
        root.def_path_hash.stable_crate_id(),
        &ArtifactAnalysisGraph::default(),
        &[InterpretationRoot {
            function: root,
            path: String::from("sample::root_80"),
            kind: ReportRootKind::Concrete,
        }],
        &config,
    )
    .expect("effect report");
    let findings = &reports[0].findings;

    assert!(findings.iter().all(|finding| !matches!(
        finding.kind,
        InterpretedFindingKind::UnresolvedCallTarget { .. }
    )));
    assert_eq!(
        findings
            .iter()
            .filter(|finding| {
                finding.effect.justification == "PANIC"
                    && matches!(finding.kind, InterpretedFindingKind::DocumentedObligation)
            })
            .count(),
        1,
    );
    assert_eq!(
        findings
            .iter()
            .filter(|finding| {
                finding.effect.justification == "SAFETY"
                    && matches!(finding.kind, InterpretedFindingKind::DocumentedObligation)
            })
            .count(),
        1,
    );
}

#[test]
fn trusted_bodyless_declarations_suppress_only_coverage_not_surface_contracts() {
    let unrelated = stable_function(0);
    let root = stable_function(10);
    let panic_declaration = stable_function(11);
    let safety_declaration = stable_function(12);

    let unrelated_panic_call = indirect_call(
        0,
        0,
        bodyless_declaration(
            panic_declaration,
            "other::PanicSurface::call",
            FunctionContractsFact::default(),
        ),
    );
    let unrelated_safety_call = indirect_call(
        1,
        1,
        bodyless_declaration(
            safety_declaration,
            "other::SafetySurface::call",
            FunctionContractsFact::default(),
        ),
    );

    let panic_call = indirect_call(
        0,
        0,
        bodyless_declaration(
            panic_declaration,
            "trusted::PanicSurface::call",
            effect_contracts(Some(whole_contract()), None),
        ),
    );

    let safety_call = indirect_call(
        1,
        1,
        bodyless_declaration(
            safety_declaration,
            "trusted::SafetySurface::call",
            effect_contracts(None, Some(whole_contract())),
        ),
    );

    let artifact = ArtifactFacts::new(
        vec![
            body(
                unrelated,
                "sample::unrelated",
                vec![unrelated_panic_call, unrelated_safety_call],
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            body(
                root,
                "sample::root",
                vec![panic_call, safety_call],
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
        ],
        Vec::new(),
    )
    .expect("bodyless declaration artifact");
    let config = trusted_declaration_config();

    let reports = trace_workspace(
        &artifact,
        root.def_path_hash.stable_crate_id(),
        &ArtifactAnalysisGraph::default(),
        &[
            InterpretationRoot {
                function: unrelated,
                path: String::from("sample::unrelated"),
                kind: ReportRootKind::Concrete,
            },
            InterpretationRoot {
                function: root,
                path: String::from("sample::root"),
                kind: ReportRootKind::Concrete,
            },
        ],
        &config,
    )
    .expect("effect report");
    assert_trusted_surface_findings(&reports);
}

fn ignored_macro_call(target_function: FunctionId, macro_definition: FunctionId) -> CallFact {
    let mut helper_call = call(0, target(target_function, "sample::helper"));
    helper_call.macro_expansions = vec![MacroExpansionFact {
        macro_def: macro_definition.def_path_hash,
        display_path: String::from("core::ub_checks::assert_unsafe_precondition"),
        source_range: None,
    }];
    helper_call
}

#[test]
fn ignored_macro_invocation_is_local_to_the_caller_report_root() {
    let boundary_root = stable_function(100);
    let helper_root = stable_function(101);
    let helper_call = ignored_macro_call(helper_root, stable_function(102));
    let compiler_assert = EffectFact {
        id: EffectId::new(0),
        effect: EffectKey::new("panic"),
        effect_group: None,
        source_range: None,
        expanded_range: None,
        macro_expansions: Vec::new(),
        kind: EffectKind::new("bounds-check"),
    };
    let artifact = ArtifactFacts::new(
        vec![
            body(
                boundary_root,
                "sample::boundary_root",
                vec![helper_call],
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            body(
                helper_root,
                "sample::helper",
                Vec::new(),
                vec![compiler_assert],
                Vec::new(),
                Vec::new(),
            ),
        ],
        Vec::new(),
    )
    .expect("path-local ignored-macro fixture");
    let config = crate::config::test_config();
    let graph = InvocationGraph::from_artifact(&artifact).expect("invocation graph");
    let namespaces = artifact.definition_namespace_index();
    let annotations = AnnotationIndex::from_artifact(&artifact, &graph).expect("annotations");
    let panic = probe_concrete_effect_for::<Panic>(
        &artifact,
        &graph,
        &annotations,
        &namespaces,
        config.effect("panic"),
    )
    .expect("panic effect");
    let trace = EffectEngine::new(&graph).trace(&panic);

    assert_eq!(trace.handled().count(), 1);
    assert_eq!(trace.escaped().count(), 0);

    let reports = trace_workspace(
        &artifact,
        boundary_root.def_path_hash.stable_crate_id(),
        &ArtifactAnalysisGraph::default(),
        &[
            InterpretationRoot {
                function: boundary_root,
                path: String::from("sample::boundary_root"),
                kind: ReportRootKind::Concrete,
            },
            InterpretationRoot {
                function: helper_root,
                path: String::from("sample::helper"),
                kind: ReportRootKind::Concrete,
            },
        ],
        &config,
    )
    .expect("effect report");
    let compiler_assert_count = |report: &RootInterpretation| {
        report
            .findings
            .iter()
            .filter(|finding| matches!(finding.kind, InterpretedFindingKind::Operation { .. }))
            .count()
    };

    assert_eq!(compiler_assert_count(&reports[0]), 0);
    assert_eq!(compiler_assert_count(&reports[1]), 1);
}

#[test]
fn ignored_macro_invocation_hides_nested_panic_marker_ambiguity_from_the_caller_root() {
    let boundary_root = stable_function(110);
    let helper_root = stable_function(111);
    let helper_call = ignored_macro_call(helper_root, stable_function(112));
    let compiler_assert = |id| EffectFact {
        id: EffectId::new(id),
        effect: EffectKey::new("panic"),
        effect_group: None,
        source_range: None,
        expanded_range: None,
        macro_expansions: Vec::new(),
        kind: EffectKind::new("bounds-check"),
    };
    let artifact = ArtifactFacts::new(
        vec![
            body(
                boundary_root,
                "sample::boundary_root",
                vec![helper_call],
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            body(
                helper_root,
                "sample::helper",
                Vec::new(),
                vec![compiler_assert(0), compiler_assert(1)],
                vec![
                    shared_justification_marker(
                        0,
                        "shared-panic-marker",
                        annotation_kind::<Panic>(AnnotationRole::Justification),
                        AnnotationTargetFact::Effect(EffectId::new(0)),
                    ),
                    shared_justification_marker(
                        1,
                        "shared-panic-marker",
                        annotation_kind::<Panic>(AnnotationRole::Justification),
                        AnnotationTargetFact::Effect(EffectId::new(1)),
                    ),
                ],
                Vec::new(),
            ),
        ],
        Vec::new(),
    )
    .expect("ignored-macro marker-ambiguity fixture");

    let reports = trace_workspace(
        &artifact,
        boundary_root.def_path_hash.stable_crate_id(),
        &ArtifactAnalysisGraph::default(),
        &[
            InterpretationRoot {
                function: boundary_root,
                path: String::from("sample::boundary_root"),
                kind: ReportRootKind::Concrete,
            },
            InterpretationRoot {
                function: helper_root,
                path: String::from("sample::helper"),
                kind: ReportRootKind::Concrete,
            },
        ],
        &crate::config::test_config(),
    )
    .expect("effect report");
    let ambiguity_count = |root| {
        reports
            .iter()
            .find(|report| report.root.function == root)
            .expect("root report")
            .findings
            .iter()
            .filter(|finding| {
                matches!(finding.kind, InterpretedFindingKind::AmbiguousMarker { .. })
            })
            .count()
    };

    assert_eq!(ambiguity_count(boundary_root), 0);
    assert_eq!(ambiguity_count(helper_root), 1);
}

#[test]
fn ignored_macro_invocation_hides_nested_unresolved_panic_gap_from_the_caller_root() {
    let boundary_root = stable_function(120);
    let helper_root = stable_function(121);
    let helper_call = ignored_macro_call(helper_root, stable_function(122));
    let artifact = ArtifactFacts::new(
        vec![
            body(
                boundary_root,
                "sample::boundary_root",
                vec![helper_call],
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            body(
                helper_root,
                "sample::helper",
                vec![targetless_call(0, 0, "unresolved function pointer")],
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
        ],
        Vec::new(),
    )
    .expect("ignored-macro unresolved-call fixture");
    let config = crate::config::test_from_manifest_str(
        r#"
                [panic.coverage]
                unresolved-call-target = "warn"
            "#,
    )
    .expect("unresolved-call configuration");

    let reports = trace_workspace(
        &artifact,
        boundary_root.def_path_hash.stable_crate_id(),
        &ArtifactAnalysisGraph::default(),
        &[
            InterpretationRoot {
                function: boundary_root,
                path: String::from("sample::boundary_root"),
                kind: ReportRootKind::Concrete,
            },
            InterpretationRoot {
                function: helper_root,
                path: String::from("sample::helper"),
                kind: ReportRootKind::Concrete,
            },
        ],
        &config,
    )
    .expect("effect report");

    assert_eq!(unresolved_panic_count(&reports, boundary_root), 0);
    assert_eq!(unresolved_panic_count(&reports, helper_root), 1);
}
