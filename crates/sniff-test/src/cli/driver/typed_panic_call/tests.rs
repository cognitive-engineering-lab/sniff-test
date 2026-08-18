use std::cell::Cell;
use std::sync::Arc;

use crate::analysis::collected::{
    CollectedArtifact, CollectedArtifactInput, CollectedCallMacroFrame, CollectedCallOccurrence,
    CollectedCallSite, CollectedCallSourceAnchor, CollectedCallTarget, CollectedFunctionBody,
    CollectedMarkerCallCandidate, CollectedMarkerOccurrence, CollectedPanicContract,
    CollectedProgram,
};
use crate::analysis::facts::collection::collect_artifact_facts;
use crate::analysis::facts::evaluation::DomainId;
use crate::analysis::facts::human::EvidenceClaimSelector;
use crate::analysis::facts::human::markers::{
    CallOccurrenceHasMarkerClaimCandidate, MarkerClaimEntity, MarkerClaimKey,
    MarkerOccurrenceEntity, MarkerOccurrenceKey,
};
use crate::analysis::facts::panic::contracts::PanicRequirement;
use crate::analysis::facts::program::topology::{
    CallAttributionRole, CallKind, CallMacroExpansionEntity, CallMacroExpansionKey,
    CallOccurrenceEntity, CallOccurrenceKey, CallSiteEntity, CallSiteKey, CallSourceAnchorRole,
    CallTargetRole, CallableEntity, SafetyEffectGroupEntity, SafetyEffectGroupKey,
};
use crate::analysis::facts::program::{
    FunctionBodyProvenance, FunctionEntity, FunctionKey, SourceAnchorEntity, SourceAnchorKey,
    SourceFileEntity,
};
use crate::analysis::facts::schema::PassId;
use crate::analysis::interpret::{InterpretationRoot, InterpretedFindingKind, interpret};
use crate::analysis::ir::{
    ArtifactAnalysisIr, CallEdgeIr, CallEdgeKindIr, CallId, CallSiteId, CallTargetIr,
    CallableAttributionIr, ContractRequirementIr, FunctionAttributesIr, FunctionBodyIr,
    FunctionBodyProvenanceIr, FunctionContractsIr, FunctionId, FunctionTargetIr,
    MacroExpansionFrameIr, MarkerId, MarkerIr, MarkerKindIr, MarkerProbingIr, MarkerSatisfactionIr,
    MarkerTargetIr, RawContractIr, SafetyEffectGroupId, SourceFileId, SourceFileIr, SourceRangeIr,
    StableInstanceHash,
};
use crate::cli::driver::interpretation::FindingSources;
use crate::cli::findings::FindingKind;
use crate::config::SniffTestConfig;
use crate::namespace::{StableDefPathHash, StableExpansionHash};
use crate::path_patterns::PathPatterns;
use crate::report_roots::ReportRootKind;
use rustc_span::{BytePos, Span};

use super::super::typed_panic::TypedPanicLocalArtifact;
use super::{
    PanicCallSemanticEdge, PanicCallSemanticTraceStepKind, adapt_typed_panic_call_finding,
    adapt_typed_panic_call_reports, evaluate_typed_panic_call_with_dependencies,
    evaluate_typed_panic_call_with_projection_fixture,
};

const LOCAL_CRATE: u64 = 1;

fn definition(local: u64) -> StableDefPathHash {
    serde_json::from_str(&format!("\"{LOCAL_CRATE:016x}{local:016x}\""))
        .expect("valid stable definition hash")
}

fn function(local: u64) -> FunctionId {
    FunctionId::generic(definition(local))
}

fn exact_function(local: u64) -> FunctionId {
    let instance = serde_json::from_str::<StableInstanceHash>(&format!("\"{local:032x}\""))
        .expect("valid stable instance hash");
    FunctionId::exact(definition(local), instance)
}

fn expansion(local: u64) -> StableExpansionHash {
    serde_json::from_str(&format!("\"{local:032x}\"")).expect("valid stable expansion hash")
}

fn key(function: FunctionId) -> FunctionKey {
    FunctionKey::new(function.def_path_hash, function.instance_hash)
}

fn root(function: FunctionId) -> InterpretationRoot {
    InterpretationRoot {
        function,
        path: String::from("fixture::root"),
        kind: ReportRootKind::Generic,
    }
}

fn empty_report(
    mut report: super::TypedPanicCallRootReport,
    request: &InterpretationRoot,
) -> super::TypedPanicCallRootReport {
    report.function = request.function;
    report.path.clone_from(&request.path);
    report.kind = request.kind;
    report.issues.clear();
    report
}

fn sink_artifact(
    root: FunctionId,
    sink: FunctionId,
) -> crate::analysis::facts::encoded::ArtifactFactIr {
    let root_key = key(root);
    let sink_key = key(sink);
    let call_site = CallSiteKey::new(root_key, 0);
    let occurrence = CallOccurrenceKey::new(root_key, 7);
    let group = SafetyEffectGroupKey::new(root_key, 0);
    let presentation = SourceAnchorKey::new("fixture-file", 20, 25);
    let expanded = SourceAnchorKey::new("fixture-file", 30, 35);
    let call = CollectedCallOccurrence::new(
        CallOccurrenceEntity::new(
            occurrence,
            CallKind::DirectCall,
            vec![
                CallAttributionRole::ErasureSite,
                CallAttributionRole::CallSite,
            ],
            false,
            false,
            None,
        ),
        vec![CollectedCallTarget::new(CallTargetRole::Runtime, sink_key)],
        Vec::new(),
        vec![group],
        vec![
            CollectedCallSourceAnchor::new(
                CallSourceAnchorRole::Presentation,
                presentation.clone(),
            ),
            CollectedCallSourceAnchor::new(CallSourceAnchorRole::Expanded, expanded.clone()),
        ],
        vec![CollectedCallMacroFrame::new(
            CallMacroExpansionEntity::new(
                CallMacroExpansionKey::new(occurrence, 0),
                expansion(1),
                definition(99),
                "fixture::call_macro",
            ),
            Some(presentation.clone()),
        )],
    );
    let program = CollectedProgram::try_new(
        vec![SourceFileEntity::new(
            "fixture-file",
            "src/lib.rs",
            "sha256:typed-panic-call-fixture",
            128,
        )],
        vec![
            SourceAnchorEntity::new(presentation),
            SourceAnchorEntity::new(expanded),
        ],
        vec![
            CallableEntity::new(
                root_key,
                "fixture::root",
                false,
                true,
                true,
                false,
                vec![String::from("fixture::root")],
            ),
            CallableEntity::new(
                sink_key,
                "fixture::sink",
                false,
                true,
                false,
                false,
                vec![String::from("fixture::sink")],
            ),
        ],
        vec![CollectedFunctionBody::new(
            FunctionEntity::new(
                root_key,
                "fixture::root",
                FunctionBodyProvenance::DefiningArtifact,
            ),
            None,
            vec![CollectedCallSite::new(
                CallSiteEntity::new(call_site),
                vec![call],
            )],
            vec![SafetyEffectGroupEntity::new(group)],
            Vec::new(),
        )],
    )
    .expect("valid panic-call fixture");
    let artifact = CollectedArtifact::try_new(CollectedArtifactInput {
        program,
        unsafe_operations: Vec::new(),
        panic_contracts: Vec::new(),
        safety_contracts: Vec::new(),
        mir_asserts: Vec::new(),
        marker_occurrences: Vec::new(),
    })
    .expect("valid collected panic-call fixture");
    collect_artifact_facts(&artifact).expect("permanent call fact collection succeeds")
}

fn range(byte_start: u64, byte_end: u64) -> SourceRangeIr {
    SourceRangeIr {
        file: SourceFileId::new("fixture-file"),
        byte_start,
        byte_end,
    }
}

fn legacy_sink_artifact(root: FunctionId, sink: FunctionId) -> ArtifactAnalysisIr {
    let call = CallEdgeIr {
        id: CallId::new(7),
        call_site: CallSiteId::new(0),
        kind: CallEdgeKindIr::DirectCall,
        safety_effect_group: Some(SafetyEffectGroupId::new(0)),
        requires_unsafe: false,
        inside_builtin_unsafe: false,
        source_range: Some(range(20, 25)),
        expanded_range: Some(range(30, 35)),
        macro_expansions: vec![MacroExpansionFrameIr {
            macro_def: definition(99),
            display_path: String::from("fixture::call_macro"),
            source_range: Some(range(20, 25)),
        }],
        callee_range: None,
        applicable_attribution: vec![
            CallableAttributionIr::ErasureSites,
            CallableAttributionIr::CallSites,
        ],
        callable_keys: Vec::new(),
        source_target: None,
        target: CallTargetIr::Function(FunctionTargetIr {
            function: sink,
            display_path: String::from("fixture::sink"),
            attributes: FunctionAttributesIr {
                is_unsafe: false,
                is_exported: true,
                has_rust_body: false,
                is_foreign: false,
                namespace_candidates: vec![String::from("fixture::sink")],
            },
            contracts: FunctionContractsIr::default(),
        }),
    };
    ArtifactAnalysisIr::new(
        vec![FunctionBodyIr {
            function: root,
            provenance: FunctionBodyProvenanceIr::DefiningArtifact,
            display_path: String::from("fixture::root"),
            attributes: FunctionAttributesIr {
                is_unsafe: false,
                is_exported: true,
                has_rust_body: true,
                is_foreign: false,
                namespace_candidates: vec![String::from("fixture::root")],
            },
            source_range: Some(range(5, 10)),
            calls: vec![call],
            effects: Vec::new(),
            markers: Vec::new(),
        }],
        vec![SourceFileIr {
            id: SourceFileId::new("fixture-file"),
            filename: String::from("src/lib.rs"),
            content_hash: String::from("sha256:typed-panic-call-fixture"),
            byte_len: 128,
        }],
    )
    .expect("valid legacy panic-call fixture")
}

#[allow(
    clippy::too_many_lines,
    reason = "the nested fixture keeps followed-call and macro provenance explicit"
)]
fn nested_sink_artifact(
    root: FunctionId,
    helper: FunctionId,
    sink: FunctionId,
) -> crate::analysis::facts::encoded::ArtifactFactIr {
    let root_key = key(root);
    let helper_key = key(helper);
    let sink_key = key(sink);
    let root_occurrence = CallOccurrenceKey::new(root_key, 6);
    let helper_occurrence = CallOccurrenceKey::new(helper_key, 7);
    let root_group = SafetyEffectGroupKey::new(root_key, 0);
    let helper_group = SafetyEffectGroupKey::new(helper_key, 0);
    let root_presentation = SourceAnchorKey::new("fixture-file", 20, 25);
    let inner_macro_callsite = SourceAnchorKey::new("fixture-file", 26, 29);
    let root_expanded = SourceAnchorKey::new("fixture-file", 30, 35);
    let helper_presentation = SourceAnchorKey::new("fixture-file", 60, 65);
    let helper_expanded = SourceAnchorKey::new("fixture-file", 70, 75);
    let root_call = CollectedCallOccurrence::new(
        CallOccurrenceEntity::new(
            root_occurrence,
            CallKind::DirectCall,
            vec![
                CallAttributionRole::ErasureSite,
                CallAttributionRole::CallSite,
            ],
            false,
            false,
            None,
        ),
        vec![CollectedCallTarget::new(
            CallTargetRole::Runtime,
            helper_key,
        )],
        Vec::new(),
        vec![root_group],
        vec![
            CollectedCallSourceAnchor::new(
                CallSourceAnchorRole::Presentation,
                root_presentation.clone(),
            ),
            CollectedCallSourceAnchor::new(CallSourceAnchorRole::Expanded, root_expanded.clone()),
        ],
        vec![
            CollectedCallMacroFrame::new(
                CallMacroExpansionEntity::new(
                    CallMacroExpansionKey::new(root_occurrence, 0),
                    expansion(10),
                    definition(91),
                    "fixture::outer",
                ),
                Some(root_presentation.clone()),
            ),
            CollectedCallMacroFrame::new(
                CallMacroExpansionEntity::new(
                    CallMacroExpansionKey::new(root_occurrence, 1),
                    expansion(11),
                    definition(92),
                    "fixture::inner",
                ),
                Some(inner_macro_callsite.clone()),
            ),
        ],
    );
    let helper_call = CollectedCallOccurrence::new(
        CallOccurrenceEntity::new(
            helper_occurrence,
            CallKind::DirectCall,
            vec![
                CallAttributionRole::ErasureSite,
                CallAttributionRole::CallSite,
            ],
            false,
            false,
            None,
        ),
        vec![CollectedCallTarget::new(CallTargetRole::Runtime, sink_key)],
        Vec::new(),
        vec![helper_group],
        vec![
            CollectedCallSourceAnchor::new(
                CallSourceAnchorRole::Presentation,
                helper_presentation.clone(),
            ),
            CollectedCallSourceAnchor::new(CallSourceAnchorRole::Expanded, helper_expanded.clone()),
        ],
        vec![CollectedCallMacroFrame::new(
            CallMacroExpansionEntity::new(
                CallMacroExpansionKey::new(helper_occurrence, 0),
                expansion(12),
                definition(93),
                "fixture::terminal_macro",
            ),
            Some(helper_presentation.clone()),
        )],
    );
    let program = CollectedProgram::try_new(
        vec![SourceFileEntity::new(
            "fixture-file",
            "src/lib.rs",
            "sha256:typed-panic-call-fixture",
            128,
        )],
        [
            root_presentation,
            inner_macro_callsite,
            root_expanded,
            helper_presentation,
            helper_expanded,
        ]
        .into_iter()
        .map(SourceAnchorEntity::new)
        .collect(),
        vec![
            CallableEntity::new(
                root_key,
                "fixture::root",
                false,
                true,
                true,
                false,
                vec![String::from("fixture::root")],
            ),
            CallableEntity::new(
                helper_key,
                "fixture::helper",
                false,
                false,
                true,
                false,
                vec![String::from("fixture::helper")],
            ),
            CallableEntity::new(
                sink_key,
                "fixture::sink",
                false,
                true,
                false,
                false,
                vec![String::from("fixture::sink")],
            ),
        ],
        vec![
            CollectedFunctionBody::new(
                FunctionEntity::new(
                    root_key,
                    "fixture::root",
                    FunctionBodyProvenance::DefiningArtifact,
                ),
                None,
                vec![CollectedCallSite::new(
                    CallSiteEntity::new(CallSiteKey::new(root_key, 0)),
                    vec![root_call],
                )],
                vec![SafetyEffectGroupEntity::new(root_group)],
                Vec::new(),
            ),
            CollectedFunctionBody::new(
                FunctionEntity::new(
                    helper_key,
                    "fixture::helper",
                    FunctionBodyProvenance::DefiningArtifact,
                ),
                None,
                vec![CollectedCallSite::new(
                    CallSiteEntity::new(CallSiteKey::new(helper_key, 0)),
                    vec![helper_call],
                )],
                vec![SafetyEffectGroupEntity::new(helper_group)],
                Vec::new(),
            ),
        ],
    )
    .expect("valid nested sink program");
    let artifact = CollectedArtifact::try_new(CollectedArtifactInput {
        program,
        unsafe_operations: Vec::new(),
        panic_contracts: Vec::new(),
        safety_contracts: Vec::new(),
        mir_asserts: Vec::new(),
        marker_occurrences: Vec::new(),
    })
    .expect("valid nested sink artifact");
    collect_artifact_facts(&artifact).expect("nested sink collection succeeds")
}

#[allow(
    clippy::too_many_lines,
    reason = "the legacy fixture mirrors every followed-call and macro trace field"
)]
fn legacy_nested_sink_artifact(
    root: FunctionId,
    helper: FunctionId,
    sink: FunctionId,
) -> ArtifactAnalysisIr {
    let attributes = |path: &str, has_rust_body| FunctionAttributesIr {
        is_unsafe: false,
        is_exported: true,
        has_rust_body,
        is_foreign: false,
        namespace_candidates: vec![path.to_owned()],
    };
    let target = |function, path: &str, has_rust_body| {
        CallTargetIr::Function(FunctionTargetIr {
            function,
            display_path: path.to_owned(),
            attributes: attributes(path, has_rust_body),
            contracts: FunctionContractsIr::default(),
        })
    };
    let call = |id, source, expanded, macro_expansions, target: CallTargetIr| -> CallEdgeIr {
        CallEdgeIr {
            id: CallId::new(id),
            call_site: CallSiteId::new(0),
            kind: CallEdgeKindIr::DirectCall,
            safety_effect_group: Some(SafetyEffectGroupId::new(0)),
            requires_unsafe: false,
            inside_builtin_unsafe: false,
            source_range: Some(source),
            expanded_range: Some(expanded),
            macro_expansions,
            callee_range: None,
            applicable_attribution: vec![
                CallableAttributionIr::ErasureSites,
                CallableAttributionIr::CallSites,
            ],
            callable_keys: Vec::new(),
            source_target: None,
            target,
        }
    };
    let root_call = call(
        6,
        range(20, 25),
        range(30, 35),
        vec![
            MacroExpansionFrameIr {
                macro_def: definition(91),
                display_path: String::from("fixture::outer"),
                source_range: Some(range(20, 25)),
            },
            MacroExpansionFrameIr {
                macro_def: definition(92),
                display_path: String::from("fixture::inner"),
                source_range: Some(range(26, 29)),
            },
        ],
        target(helper, "fixture::helper", true),
    );
    let helper_call = call(
        7,
        range(60, 65),
        range(70, 75),
        vec![MacroExpansionFrameIr {
            macro_def: definition(93),
            display_path: String::from("fixture::terminal_macro"),
            source_range: Some(range(60, 65)),
        }],
        target(sink, "fixture::sink", false),
    );
    ArtifactAnalysisIr::new(
        vec![
            FunctionBodyIr {
                function: root,
                provenance: FunctionBodyProvenanceIr::DefiningArtifact,
                display_path: String::from("fixture::root"),
                attributes: attributes("fixture::root", true),
                source_range: Some(range(5, 10)),
                calls: vec![root_call],
                effects: Vec::new(),
                markers: Vec::new(),
            },
            FunctionBodyIr {
                function: helper,
                provenance: FunctionBodyProvenanceIr::DefiningArtifact,
                display_path: String::from("fixture::helper"),
                attributes: attributes("fixture::helper", true),
                source_range: Some(range(40, 45)),
                calls: vec![helper_call],
                effects: Vec::new(),
                markers: Vec::new(),
            },
        ],
        vec![SourceFileIr {
            id: SourceFileId::new("fixture-file"),
            filename: String::from("src/lib.rs"),
            content_hash: String::from("sha256:typed-panic-call-fixture"),
            byte_len: 128,
        }],
    )
    .expect("valid legacy nested sink fixture")
}

fn targetless_opaque_artifact(
    root: FunctionId,
    requires_unsafe: bool,
) -> crate::analysis::facts::encoded::ArtifactFactIr {
    let root_key = key(root);
    let call_site = CallSiteKey::new(root_key, 0);
    let occurrence = CallOccurrenceKey::new(root_key, 9);
    let group = SafetyEffectGroupKey::new(root_key, 0);
    let presentation = SourceAnchorKey::new("fixture-file", 20, 25);
    let expanded = SourceAnchorKey::new("fixture-file", 30, 35);
    let call = CollectedCallOccurrence::new(
        CallOccurrenceEntity::new(
            occurrence,
            CallKind::IndirectCall,
            vec![
                CallAttributionRole::ErasureSite,
                CallAttributionRole::CallSite,
            ],
            requires_unsafe,
            false,
            Some(String::from("rustc-specific unsafe fn pointer spelling")),
        ),
        Vec::new(),
        Vec::new(),
        vec![group],
        vec![
            CollectedCallSourceAnchor::new(
                CallSourceAnchorRole::Presentation,
                presentation.clone(),
            ),
            CollectedCallSourceAnchor::new(CallSourceAnchorRole::Expanded, expanded.clone()),
        ],
        Vec::new(),
    );
    let program = CollectedProgram::try_new(
        vec![SourceFileEntity::new(
            "fixture-file",
            "src/lib.rs",
            "sha256:typed-panic-call-fixture",
            128,
        )],
        vec![
            SourceAnchorEntity::new(presentation),
            SourceAnchorEntity::new(expanded),
        ],
        vec![CallableEntity::new(
            root_key,
            "fixture::root",
            false,
            true,
            true,
            false,
            vec![String::from("fixture::root")],
        )],
        vec![CollectedFunctionBody::new(
            FunctionEntity::new(
                root_key,
                "fixture::root",
                FunctionBodyProvenance::DefiningArtifact,
            ),
            None,
            vec![CollectedCallSite::new(
                CallSiteEntity::new(call_site),
                vec![call],
            )],
            vec![SafetyEffectGroupEntity::new(group)],
            Vec::new(),
        )],
    )
    .expect("valid targetless opaque program");
    let artifact = CollectedArtifact::try_new(CollectedArtifactInput {
        program,
        unsafe_operations: Vec::new(),
        panic_contracts: Vec::new(),
        safety_contracts: Vec::new(),
        mir_asserts: Vec::new(),
        marker_occurrences: Vec::new(),
    })
    .expect("valid targetless opaque artifact");
    collect_artifact_facts(&artifact).expect("targetless opaque collection succeeds")
}

fn legacy_targetless_opaque_artifact(
    root: FunctionId,
    requires_unsafe: bool,
) -> ArtifactAnalysisIr {
    let call = CallEdgeIr {
        id: CallId::new(9),
        call_site: CallSiteId::new(0),
        kind: CallEdgeKindIr::IndirectCall,
        safety_effect_group: Some(SafetyEffectGroupId::new(0)),
        requires_unsafe,
        inside_builtin_unsafe: false,
        source_range: Some(range(20, 25)),
        expanded_range: Some(range(30, 35)),
        macro_expansions: Vec::new(),
        callee_range: None,
        applicable_attribution: vec![
            CallableAttributionIr::ErasureSites,
            CallableAttributionIr::CallSites,
        ],
        callable_keys: Vec::new(),
        source_target: None,
        target: CallTargetIr::OpaqueBoundary {
            description: String::from("rustc-specific unsafe fn pointer spelling"),
            target: None,
        },
    };
    ArtifactAnalysisIr::new(
        vec![FunctionBodyIr {
            function: root,
            provenance: FunctionBodyProvenanceIr::DefiningArtifact,
            display_path: String::from("fixture::root"),
            attributes: FunctionAttributesIr {
                is_unsafe: false,
                is_exported: true,
                has_rust_body: true,
                is_foreign: false,
                namespace_candidates: vec![String::from("fixture::root")],
            },
            source_range: Some(range(5, 10)),
            calls: vec![call],
            effects: Vec::new(),
            markers: Vec::new(),
        }],
        vec![SourceFileIr {
            id: SourceFileId::new("fixture-file"),
            filename: String::from("src/lib.rs"),
            content_hash: String::from("sha256:typed-panic-call-fixture"),
            byte_len: 128,
        }],
    )
    .expect("valid legacy targetless opaque fixture")
}

#[allow(
    clippy::too_many_lines,
    reason = "the complete permanent-fact fixture keeps each duplicate provenance row visible"
)]
fn documented_duplicate_artifact(
    root: FunctionId,
    documented: FunctionId,
) -> crate::analysis::facts::encoded::ArtifactFactIr {
    let root_key = key(root);
    let documented_key = key(documented);
    let call_site = CallSiteKey::new(root_key, 0);
    let occurrence = CallOccurrenceKey::new(root_key, 3);
    let group = SafetyEffectGroupKey::new(root_key, 0);
    let call_presentation = SourceAnchorKey::new("fixture-file", 20, 25);
    let call_expanded = SourceAnchorKey::new("fixture-file", 30, 35);
    let marker_anchor = SourceAnchorKey::new("fixture-file", 40, 45);
    let contract_anchor = SourceAnchorKey::new("fixture-file", 50, 55);
    let requirement_anchors = [
        SourceAnchorKey::new("fixture-file", 60, 65),
        SourceAnchorKey::new("fixture-file", 70, 75),
        SourceAnchorKey::new("fixture-file", 80, 85),
        SourceAnchorKey::new("fixture-file", 90, 95),
    ];
    let call = CollectedCallOccurrence::new(
        CallOccurrenceEntity::new(
            occurrence,
            CallKind::DirectCall,
            vec![
                CallAttributionRole::ErasureSite,
                CallAttributionRole::CallSite,
            ],
            false,
            false,
            None,
        ),
        vec![CollectedCallTarget::new(
            CallTargetRole::Runtime,
            documented_key,
        )],
        Vec::new(),
        vec![group],
        vec![
            CollectedCallSourceAnchor::new(
                CallSourceAnchorRole::Presentation,
                call_presentation.clone(),
            ),
            CollectedCallSourceAnchor::new(CallSourceAnchorRole::Expanded, call_expanded.clone()),
        ],
        Vec::new(),
    );
    let marker_occurrence = MarkerOccurrenceKey::new(marker_anchor.clone(), None);
    let claims = ["index in bounds", "ready"]
        .into_iter()
        .enumerate()
        .map(|(ordinal, name)| {
            MarkerClaimEntity::new(
                MarkerClaimKey::new(
                    marker_occurrence.clone(),
                    DomainId::new("sniff-test.panic").unwrap(),
                    u32::try_from(ordinal).unwrap(),
                ),
                EvidenceClaimSelector::Named(name.to_owned()),
                "fixture proves the named requirement",
            )
        })
        .collect::<Vec<_>>();
    let marker = CollectedMarkerOccurrence::new(
        MarkerOccurrenceEntity::new(marker_occurrence, Vec::new()),
        claims.clone(),
        Vec::new(),
        claims
            .iter()
            .map(|claim| {
                CollectedMarkerCallCandidate::new(
                    occurrence,
                    claim.key().clone(),
                    CallOccurrenceHasMarkerClaimCandidate::new(true, true),
                )
            })
            .collect(),
        Vec::new(),
        Vec::new(),
    );
    let requirements = [
        ("Index_In-Bounds", "the index is valid"),
        ("index-in_bounds", "the index remains valid"),
        ("Ready", "the value is ready"),
        ("READY", "the value remains ready"),
    ]
    .into_iter()
    .enumerate()
    .map(|(ordinal, (name, condition))| {
        PanicRequirement::new(
            documented_key,
            u32::try_from(ordinal).unwrap(),
            name,
            condition,
            Some(requirement_anchors[ordinal].clone()),
        )
    })
    .collect();
    let mut anchors = vec![
        call_presentation,
        call_expanded,
        marker_anchor,
        contract_anchor.clone(),
    ];
    anchors.extend(requirement_anchors.iter().cloned());
    let program = CollectedProgram::try_new(
        vec![SourceFileEntity::new(
            "fixture-file",
            "src/lib.rs",
            "sha256:typed-panic-call-fixture",
            128,
        )],
        anchors.into_iter().map(SourceAnchorEntity::new).collect(),
        vec![
            CallableEntity::new(
                root_key,
                "fixture::root",
                false,
                true,
                true,
                false,
                vec![String::from("fixture::root")],
            ),
            CallableEntity::new(
                documented_key,
                "fixture::documented",
                false,
                true,
                false,
                false,
                vec![String::from("fixture::documented")],
            ),
        ],
        vec![CollectedFunctionBody::new(
            FunctionEntity::new(
                root_key,
                "fixture::root",
                FunctionBodyProvenance::DefiningArtifact,
            ),
            None,
            vec![CollectedCallSite::new(
                CallSiteEntity::new(call_site),
                vec![call],
            )],
            vec![SafetyEffectGroupEntity::new(group)],
            Vec::new(),
        )],
    )
    .expect("valid documented duplicate program");
    let artifact = CollectedArtifact::try_new(CollectedArtifactInput {
        program,
        unsafe_operations: Vec::new(),
        panic_contracts: vec![CollectedPanicContract::new(
            documented_key,
            Some(contract_anchor),
            requirements,
        )],
        safety_contracts: Vec::new(),
        mir_asserts: Vec::new(),
        marker_occurrences: vec![marker],
    })
    .expect("valid documented duplicate artifact");
    collect_artifact_facts(&artifact).expect("documented duplicate collection succeeds")
}

fn legacy_documented_duplicate_artifact(
    root: FunctionId,
    documented: FunctionId,
) -> ArtifactAnalysisIr {
    let requirements = [
        ("Index_In-Bounds", "the index is valid", 60, 65),
        ("index-in_bounds", "the index remains valid", 70, 75),
        ("Ready", "the value is ready", 80, 85),
        ("READY", "the value remains ready", 90, 95),
    ]
    .into_iter()
    .map(|(name, condition, start, end)| ContractRequirementIr {
        name: name.to_owned(),
        condition: condition.to_owned(),
        source_range: Some(range(start, end)),
    })
    .collect();
    let call = CallEdgeIr {
        id: CallId::new(3),
        call_site: CallSiteId::new(0),
        kind: CallEdgeKindIr::DirectCall,
        safety_effect_group: Some(SafetyEffectGroupId::new(0)),
        requires_unsafe: false,
        inside_builtin_unsafe: false,
        source_range: Some(range(20, 25)),
        expanded_range: Some(range(30, 35)),
        macro_expansions: Vec::new(),
        callee_range: None,
        applicable_attribution: vec![
            CallableAttributionIr::ErasureSites,
            CallableAttributionIr::CallSites,
        ],
        callable_keys: Vec::new(),
        source_target: None,
        target: CallTargetIr::Function(FunctionTargetIr {
            function: documented,
            display_path: String::from("fixture::documented"),
            attributes: FunctionAttributesIr {
                is_unsafe: false,
                is_exported: true,
                has_rust_body: false,
                is_foreign: false,
                namespace_candidates: vec![String::from("fixture::documented")],
            },
            contracts: FunctionContractsIr {
                panic: Some(RawContractIr {
                    source_range: Some(range(50, 55)),
                    requirements,
                }),
                safety: None,
            },
        }),
    };
    let marker = MarkerIr {
        id: MarkerId::new(0),
        identity: String::from("duplicate-satisfaction-marker"),
        kind: MarkerKindIr::PanicJustification,
        source_range: Some(range(40, 45)),
        target: MarkerTargetIr::Call(CallId::new(3)),
        applicable_probing: vec![
            MarkerProbingIr::SourceCallsite,
            MarkerProbingIr::MacroDefinitionFirst,
        ],
        satisfactions: ["index in bounds", "ready"]
            .into_iter()
            .map(|requirement| MarkerSatisfactionIr {
                requirement: Some(requirement.to_owned()),
                reason: String::from("fixture proves the named requirement"),
            })
            .collect(),
        requirements: Vec::new(),
    };
    ArtifactAnalysisIr::new(
        vec![FunctionBodyIr {
            function: root,
            provenance: FunctionBodyProvenanceIr::DefiningArtifact,
            display_path: String::from("fixture::root"),
            attributes: FunctionAttributesIr {
                is_unsafe: false,
                is_exported: true,
                has_rust_body: true,
                is_foreign: false,
                namespace_candidates: vec![String::from("fixture::root")],
            },
            source_range: Some(range(5, 10)),
            calls: vec![call],
            effects: Vec::new(),
            markers: vec![marker],
        }],
        vec![SourceFileIr {
            id: SourceFileId::new("fixture-file"),
            filename: String::from("src/lib.rs"),
            content_hash: String::from("sha256:typed-panic-call-fixture"),
            byte_len: 128,
        }],
    )
    .expect("valid legacy duplicate fixture")
}

#[allow(
    clippy::too_many_lines,
    reason = "the two-call fixture keeps traversal and requirement provenance explicit"
)]
fn mixed_documented_artifact(
    root: FunctionId,
    first_documented: FunctionId,
    second_documented: FunctionId,
) -> crate::analysis::facts::encoded::ArtifactFactIr {
    let root_key = key(root);
    let first_key = key(first_documented);
    let second_key = key(second_documented);
    let first_call_site = CallSiteKey::new(root_key, 0);
    let second_call_site = CallSiteKey::new(root_key, 1);
    let first_occurrence = CallOccurrenceKey::new(root_key, 3);
    let second_occurrence = CallOccurrenceKey::new(root_key, 4);
    let first_group = SafetyEffectGroupKey::new(root_key, 0);
    let second_group = SafetyEffectGroupKey::new(root_key, 1);
    let first_presentation = SourceAnchorKey::new("fixture-file", 20, 25);
    let first_expanded = SourceAnchorKey::new("fixture-file", 30, 35);
    let first_contract = SourceAnchorKey::new("fixture-file", 40, 45);
    let first_requirement_anchors = [
        SourceAnchorKey::new("fixture-file", 50, 55),
        SourceAnchorKey::new("fixture-file", 60, 65),
        SourceAnchorKey::new("fixture-file", 70, 75),
        SourceAnchorKey::new("fixture-file", 80, 85),
    ];
    let marker_anchor = SourceAnchorKey::new("fixture-file", 90, 95);
    let second_presentation = SourceAnchorKey::new("fixture-file", 120, 125);
    let second_expanded = SourceAnchorKey::new("fixture-file", 130, 135);
    let second_contract = SourceAnchorKey::new("fixture-file", 140, 145);
    let second_requirement_anchor = SourceAnchorKey::new("fixture-file", 150, 155);
    let call = |occurrence,
                target,
                group,
                presentation: &SourceAnchorKey,
                expanded: &SourceAnchorKey| {
        CollectedCallOccurrence::new(
            CallOccurrenceEntity::new(
                occurrence,
                CallKind::DirectCall,
                vec![
                    CallAttributionRole::ErasureSite,
                    CallAttributionRole::CallSite,
                ],
                false,
                false,
                None,
            ),
            vec![CollectedCallTarget::new(CallTargetRole::Runtime, target)],
            Vec::new(),
            vec![group],
            vec![
                CollectedCallSourceAnchor::new(
                    CallSourceAnchorRole::Presentation,
                    presentation.clone(),
                ),
                CollectedCallSourceAnchor::new(CallSourceAnchorRole::Expanded, expanded.clone()),
            ],
            Vec::new(),
        )
    };
    let first_requirements = [
        ("Ready", "the value is ready"),
        ("READY", "the value remains ready"),
        ("Index_In-Bounds", "the index is valid"),
        ("index-in_bounds", "the index remains valid"),
    ]
    .into_iter()
    .enumerate()
    .map(|(ordinal, (name, condition))| {
        PanicRequirement::new(
            first_key,
            u32::try_from(ordinal).unwrap(),
            name,
            condition,
            Some(first_requirement_anchors[ordinal].clone()),
        )
    })
    .collect();
    let second_requirements = vec![PanicRequirement::new(
        second_key,
        0,
        "Initialized",
        "the value is initialized",
        Some(second_requirement_anchor.clone()),
    )];
    let marker_occurrence = MarkerOccurrenceKey::new(marker_anchor.clone(), None);
    let marker_claim = MarkerClaimEntity::new(
        MarkerClaimKey::new(
            marker_occurrence.clone(),
            DomainId::new("sniff-test.panic").unwrap(),
            0,
        ),
        EvidenceClaimSelector::Named(String::from("ready")),
        "fixture proves only the ready requirement group",
    );
    let marker = CollectedMarkerOccurrence::new(
        MarkerOccurrenceEntity::new(marker_occurrence, Vec::new()),
        vec![marker_claim.clone()],
        Vec::new(),
        vec![CollectedMarkerCallCandidate::new(
            first_occurrence,
            marker_claim.key().clone(),
            CallOccurrenceHasMarkerClaimCandidate::new(true, true),
        )],
        Vec::new(),
        Vec::new(),
    );
    let mut anchors = vec![
        first_presentation.clone(),
        first_expanded.clone(),
        first_contract.clone(),
        second_presentation.clone(),
        second_expanded.clone(),
        second_contract.clone(),
        second_requirement_anchor,
        marker_anchor,
    ];
    anchors.extend(first_requirement_anchors.iter().cloned());
    let program = CollectedProgram::try_new(
        vec![SourceFileEntity::new(
            "fixture-file",
            "src/lib.rs",
            "sha256:typed-panic-call-fixture",
            256,
        )],
        anchors.into_iter().map(SourceAnchorEntity::new).collect(),
        vec![
            CallableEntity::new(
                root_key,
                "fixture::root",
                false,
                true,
                true,
                false,
                vec![String::from("fixture::root")],
            ),
            CallableEntity::new(
                first_key,
                "fixture::first_documented",
                false,
                true,
                false,
                false,
                vec![String::from("fixture::first_documented")],
            ),
            CallableEntity::new(
                second_key,
                "fixture::second_documented",
                false,
                true,
                false,
                false,
                vec![String::from("fixture::second_documented")],
            ),
        ],
        vec![CollectedFunctionBody::new(
            FunctionEntity::new(
                root_key,
                "fixture::root",
                FunctionBodyProvenance::DefiningArtifact,
            ),
            None,
            vec![
                CollectedCallSite::new(
                    CallSiteEntity::new(first_call_site),
                    vec![call(
                        first_occurrence,
                        first_key,
                        first_group,
                        &first_presentation,
                        &first_expanded,
                    )],
                ),
                CollectedCallSite::new(
                    CallSiteEntity::new(second_call_site),
                    vec![call(
                        second_occurrence,
                        second_key,
                        second_group,
                        &second_presentation,
                        &second_expanded,
                    )],
                ),
            ],
            vec![
                SafetyEffectGroupEntity::new(first_group),
                SafetyEffectGroupEntity::new(second_group),
            ],
            Vec::new(),
        )],
    )
    .expect("valid mixed documented program");
    let artifact = CollectedArtifact::try_new(CollectedArtifactInput {
        program,
        unsafe_operations: Vec::new(),
        panic_contracts: vec![
            CollectedPanicContract::new(first_key, Some(first_contract), first_requirements),
            CollectedPanicContract::new(second_key, Some(second_contract), second_requirements),
        ],
        safety_contracts: Vec::new(),
        mir_asserts: Vec::new(),
        marker_occurrences: vec![marker],
    })
    .expect("valid mixed documented artifact");
    collect_artifact_facts(&artifact).expect("mixed documented collection succeeds")
}

#[allow(
    clippy::too_many_lines,
    reason = "the legacy parity fixture intentionally mirrors both permanent call witnesses"
)]
fn legacy_mixed_documented_artifact(
    root: FunctionId,
    first_documented: FunctionId,
    second_documented: FunctionId,
) -> ArtifactAnalysisIr {
    let requirements = |entries: &[(&str, &str, u64, u64)]| {
        entries
            .iter()
            .map(|(name, condition, start, end)| ContractRequirementIr {
                name: (*name).to_owned(),
                condition: (*condition).to_owned(),
                source_range: Some(range(*start, *end)),
            })
            .collect::<Vec<_>>()
    };
    let first_requirements = requirements(&[
        ("Ready", "the value is ready", 50, 55),
        ("READY", "the value remains ready", 60, 65),
        ("Index_In-Bounds", "the index is valid", 70, 75),
        ("index-in_bounds", "the index remains valid", 80, 85),
    ]);
    let second_requirements =
        requirements(&[("Initialized", "the value is initialized", 150, 155)]);
    let target = |function, path: &str, contract_range, requirements| {
        CallTargetIr::Function(FunctionTargetIr {
            function,
            display_path: path.to_owned(),
            attributes: FunctionAttributesIr {
                is_unsafe: false,
                is_exported: true,
                has_rust_body: false,
                is_foreign: false,
                namespace_candidates: vec![path.to_owned()],
            },
            contracts: FunctionContractsIr {
                panic: Some(RawContractIr {
                    source_range: Some(contract_range),
                    requirements,
                }),
                safety: None,
            },
        })
    };
    let call = |id, call_site, group, source, expanded, target| CallEdgeIr {
        id: CallId::new(id),
        call_site: CallSiteId::new(call_site),
        kind: CallEdgeKindIr::DirectCall,
        safety_effect_group: Some(SafetyEffectGroupId::new(group)),
        requires_unsafe: false,
        inside_builtin_unsafe: false,
        source_range: Some(source),
        expanded_range: Some(expanded),
        macro_expansions: Vec::new(),
        callee_range: None,
        applicable_attribution: vec![
            CallableAttributionIr::ErasureSites,
            CallableAttributionIr::CallSites,
        ],
        callable_keys: Vec::new(),
        source_target: None,
        target,
    };
    ArtifactAnalysisIr::new(
        vec![FunctionBodyIr {
            function: root,
            provenance: FunctionBodyProvenanceIr::DefiningArtifact,
            display_path: String::from("fixture::root"),
            attributes: FunctionAttributesIr {
                is_unsafe: false,
                is_exported: true,
                has_rust_body: true,
                is_foreign: false,
                namespace_candidates: vec![String::from("fixture::root")],
            },
            source_range: Some(range(5, 10)),
            calls: vec![
                call(
                    3,
                    0,
                    0,
                    range(20, 25),
                    range(30, 35),
                    target(
                        first_documented,
                        "fixture::first_documented",
                        range(40, 45),
                        first_requirements,
                    ),
                ),
                call(
                    4,
                    1,
                    1,
                    range(120, 125),
                    range(130, 135),
                    target(
                        second_documented,
                        "fixture::second_documented",
                        range(140, 145),
                        second_requirements,
                    ),
                ),
            ],
            effects: Vec::new(),
            markers: vec![MarkerIr {
                id: MarkerId::new(0),
                identity: String::from("ready-marker"),
                kind: MarkerKindIr::PanicJustification,
                source_range: Some(range(90, 95)),
                target: MarkerTargetIr::Call(CallId::new(3)),
                applicable_probing: vec![
                    MarkerProbingIr::SourceCallsite,
                    MarkerProbingIr::MacroDefinitionFirst,
                ],
                satisfactions: vec![MarkerSatisfactionIr {
                    requirement: Some(String::from("ready")),
                    reason: String::from("fixture proves only the ready requirement group"),
                }],
                requirements: Vec::new(),
            }],
        }],
        vec![SourceFileIr {
            id: SourceFileId::new("fixture-file"),
            filename: String::from("src/lib.rs"),
            content_hash: String::from("sha256:typed-panic-call-fixture"),
            byte_len: 256,
        }],
    )
    .expect("valid mixed legacy artifact")
}

struct NoSources;

impl FindingSources for NoSources {
    fn function_span(&self, _function: FunctionId) -> Option<Span> {
        None
    }

    fn resolve(&self, _range: Option<&SourceRangeIr>) -> (Option<Span>, Option<String>) {
        (None, None)
    }

    fn source_file<'a>(&'a self, _range: &SourceRangeIr) -> Option<&'a SourceFileIr> {
        None
    }

    fn render_span(&self, _span: Span) -> String {
        String::from("unreachable")
    }
}

#[derive(Default)]
struct CountingSources {
    calls: Cell<usize>,
}

impl CountingSources {
    fn record_call(&self) {
        self.calls.set(self.calls.get() + 1);
    }
}

impl FindingSources for CountingSources {
    fn function_span(&self, _function: FunctionId) -> Option<Span> {
        self.record_call();
        None
    }

    fn resolve(&self, _range: Option<&SourceRangeIr>) -> (Option<Span>, Option<String>) {
        self.record_call();
        (None, None)
    }

    fn source_file<'a>(&'a self, _range: &SourceRangeIr) -> Option<&'a SourceFileIr> {
        self.record_call();
        None
    }

    fn render_span(&self, _span: Span) -> String {
        self.record_call();
        String::from("unreachable")
    }
}

struct FixtureSources {
    root: FunctionId,
    file: SourceFileIr,
}

impl FindingSources for FixtureSources {
    fn function_span(&self, function: FunctionId) -> Option<Span> {
        (function == self.root).then(|| Span::with_root_ctxt(BytePos(5), BytePos(10)))
    }

    fn resolve(&self, range: Option<&SourceRangeIr>) -> (Option<Span>, Option<String>) {
        let Some(range) = range else {
            return (None, None);
        };
        if range.file != self.file.id {
            return (None, Some(String::from("unknown source identity")));
        }
        let start = u32::try_from(range.byte_start).expect("fixture start fits u32");
        let end = u32::try_from(range.byte_end).expect("fixture end fits u32");
        (
            Some(Span::with_root_ctxt(BytePos(start), BytePos(end))),
            None,
        )
    }

    fn source_file<'a>(&'a self, range: &SourceRangeIr) -> Option<&'a SourceFileIr> {
        (range.file == self.file.id).then_some(&self.file)
    }

    fn render_span(&self, span: Span) -> String {
        format!("bytes {}..{}", span.lo().0, span.hi().0)
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one parity test freezes ordering and full Finding equality for both policies"
)]
fn mixed_documented_issues_follow_traversal_and_legacy_finding_order() {
    let root_function = function(20);
    let first_documented = exact_function(21);
    let second_documented = exact_function(22);
    let facts = mixed_documented_artifact(root_function, first_documented, second_documented);
    let legacy =
        legacy_mixed_documented_artifact(root_function, first_documented, second_documented);
    let requested_root = root(root_function);
    let sources = FixtureSources {
        root: root_function,
        file: SourceFileIr {
            id: SourceFileId::new("fixture-file"),
            filename: String::from("src/lib.rs"),
            content_hash: String::from("sha256:typed-panic-call-fixture"),
            byte_len: 256,
        },
    };

    for trusted in [false, true] {
        let mut config = SniffTestConfig::default();
        if trusted {
            config.panics.trusted_panic_boundary_namespaces = PathPatterns::new(vec![
                String::from("fixture::first_documented"),
                String::from("fixture::second_documented"),
            ])
            .unwrap();
        }
        let report = evaluate_typed_panic_call_with_dependencies(
            TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
            [],
            &[],
            &requested_root,
            &config,
        )
        .expect("mixed documented evaluation succeeds");

        let issue_order = report
            .issues
            .iter()
            .map(|issue| match &issue.kind {
                super::TypedPanicCallIssueKind::Duplicate { normalized_name } => {
                    format!("duplicate:{normalized_name}")
                }
                super::TypedPanicCallIssueKind::Unsatisfied { .. } => {
                    format!("unsatisfied:{}", issue.target.path)
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(
            issue_order,
            [
                String::from("duplicate:index in bounds"),
                String::from("duplicate:ready"),
                String::from("unsatisfied:fixture::first_documented"),
                String::from("unsatisfied:fixture::second_documented"),
            ]
        );
        assert!(matches!(
            report.issues[2].kind,
            super::TypedPanicCallIssueKind::Unsatisfied {
                boundary: super::PanicCallBoundaryKind::Documented {
                    trusted: issue_trusted,
                },
            } if issue_trusted == trusted
        ));
        assert!(matches!(
            report.issues[3].kind,
            super::TypedPanicCallIssueKind::Unsatisfied {
                boundary: super::PanicCallBoundaryKind::Documented {
                    trusted: issue_trusted,
                },
            } if issue_trusted == trusted
        ));
        let first_missing = report.issues[2]
            .missing_requirements
            .iter()
            .map(|requirement| requirement.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(first_missing, ["Index_In-Bounds", "index-in_bounds"]);
        assert_eq!(
            report.issues[2]
                .requirements
                .iter()
                .map(|requirement| requirement.name.as_str())
                .collect::<Vec<_>>(),
            ["Ready", "READY", "Index_In-Bounds", "index-in_bounds"]
        );
        assert_eq!(report.issues[3].missing_requirements[0].name, "Initialized");

        let legacy_report = interpret(&legacy, std::slice::from_ref(&requested_root), &config);
        assert_eq!(legacy_report[0].findings.len(), 4);
        for show_full_stack_trace in [false, true] {
            let expected = legacy_report[0]
                .findings
                .iter()
                .map(|finding| {
                    adapt_typed_panic_call_finding(
                        &sources,
                        &requested_root,
                        finding,
                        show_full_stack_trace,
                    )
                })
                .collect::<Vec<_>>();
            let actual = adapt_typed_panic_call_reports(
                &sources,
                vec![report.clone()],
                std::slice::from_ref(&requested_root),
                show_full_stack_trace,
            )
            .expect("mixed documented report adapts through the legacy boundary");
            assert_eq!(actual, expected);
            assert_eq!(
                actual[2].kind,
                if trusted {
                    FindingKind::TrustedPanic
                } else {
                    FindingKind::DocumentedPanic
                }
            );
        }
    }
}

#[test]
fn obligation_index_rejects_hostile_dense_join_shapes() {
    let mixed_root_function = function(70);
    let mixed_facts =
        mixed_documented_artifact(mixed_root_function, exact_function(71), exact_function(72));
    let mixed_request = root(mixed_root_function);
    let (mixed, mixed_fixture) = evaluate_typed_panic_call_with_projection_fixture(
        TypedPanicLocalArtifact::in_memory(&mixed_facts, LOCAL_CRATE),
        [],
        &[],
        &mixed_request,
        &SniffTestConfig::default(),
    )
    .expect("mixed projection fixture evaluates");
    assert_eq!(
        super::index_obligations(
            &mixed_fixture.inputs,
            &mixed.root,
            mixed_fixture.obligations.clone(),
        )
        .unwrap()
        .len(),
        2
    );

    let sink_root_function = function(73);
    let sink_facts = sink_artifact(sink_root_function, exact_function(74));
    let sink_request = root(sink_root_function);
    let mut sink_config = SniffTestConfig::default();
    sink_config.panics.panic_sink_namespaces =
        PathPatterns::new(vec![String::from("fixture::sink")]).unwrap();
    let (sink, sink_fixture) = evaluate_typed_panic_call_with_projection_fixture(
        TypedPanicLocalArtifact::in_memory(&sink_facts, LOCAL_CRATE),
        [],
        &[],
        &sink_request,
        &sink_config,
    )
    .expect("single-call projection fixture evaluates");

    let mut wrong_root = mixed_fixture.obligations.clone();
    wrong_root[0].root.domain = DomainId::new("hostile.panic").unwrap();
    let mut wrong_producer = mixed_fixture.obligations.clone();
    wrong_producer[0].producer = PassId::new("hostile.producer").unwrap();
    let mut missing = mixed_fixture.obligations.clone();
    missing.pop();
    let mut duplicate = mixed_fixture.obligations.clone();
    duplicate.push(duplicate[0].clone());
    let mut out_of_range = mixed_fixture
        .obligations
        .iter()
        .find(|row| row.data.call_id() == 1)
        .expect("mixed fixture has witness one")
        .clone();
    out_of_range.root = sink.root.clone();

    let cases = vec![
        (
            "wrong root",
            &mixed_fixture.inputs,
            &mixed.root,
            wrong_root,
            "root or producer",
        ),
        (
            "wrong producer",
            &mixed_fixture.inputs,
            &mixed.root,
            wrong_producer,
            "root or producer",
        ),
        (
            "missing dense ID",
            &mixed_fixture.inputs,
            &mixed.root,
            missing,
            "is missing",
        ),
        (
            "duplicate dense ID",
            &mixed_fixture.inputs,
            &mixed.root,
            duplicate,
            "is duplicated",
        ),
        (
            "out-of-range dense ID",
            &sink_fixture.inputs,
            &sink.root,
            vec![out_of_range],
            "outside the prepared input batch",
        ),
    ];
    for (name, inputs, evaluation_root, rows, expected) in cases {
        let error = super::index_obligations(inputs, evaluation_root, rows).expect_err(name);
        assert!(
            error.to_string().contains(expected),
            "{name}: expected `{expected}`, got `{error}`"
        );
    }
}

#[test]
fn issue_validators_reject_cross_witness_and_hostile_context_joins() {
    let root_function = function(80);
    let facts = mixed_documented_artifact(root_function, exact_function(81), exact_function(82));
    let requested_root = root(root_function);
    let (report, fixture) = evaluate_typed_panic_call_with_projection_fixture(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        [],
        &[],
        &requested_root,
        &SniffTestConfig::default(),
    )
    .expect("mixed projection fixture evaluates");
    let obligations =
        super::index_obligations(&fixture.inputs, &report.root, fixture.obligations.clone())
            .unwrap();
    let unsatisfied_zero = fixture
        .unsatisfied
        .iter()
        .find(|issue| issue.data.witness_order() == 0)
        .unwrap()
        .clone();
    let unsatisfied_one = fixture
        .unsatisfied
        .iter()
        .find(|issue| issue.data.witness_order() == 1)
        .unwrap()
        .clone();
    super::validate_unsatisfied_issue(&report.root, &obligations[0], &unsatisfied_zero).unwrap();
    let mut unsatisfied_source = unsatisfied_zero.clone();
    unsatisfied_source.context.source = None;
    let mut unsatisfied_endpoint = unsatisfied_zero.clone();
    unsatisfied_endpoint.context.endpoint = None;
    let mut unsatisfied_trace = unsatisfied_zero.clone();
    unsatisfied_trace.context.trace = None;
    for (name, obligation, issue) in [
        ("cross witness", &obligations[0], unsatisfied_one),
        ("wrong source context", &obligations[0], unsatisfied_source),
        (
            "wrong endpoint context",
            &obligations[0],
            unsatisfied_endpoint,
        ),
        ("wrong trace context", &obligations[0], unsatisfied_trace),
    ] {
        assert!(
            super::validate_unsatisfied_issue(&report.root, obligation, &issue).is_err(),
            "unsatisfied validator accepted {name}"
        );
    }

    let duplicate = fixture.duplicates.first().unwrap().clone();
    super::validate_duplicate_issue(&report.root, &obligations[0], &duplicate).unwrap();
    let mut duplicate_source = duplicate.clone();
    duplicate_source.context.source = None;
    let mut duplicate_endpoint = duplicate.clone();
    duplicate_endpoint.context.endpoint = None;
    let mut duplicate_trace = duplicate.clone();
    duplicate_trace.context.trace = None;
    for (name, obligation, issue) in [
        ("cross witness", &obligations[1], duplicate.clone()),
        ("wrong source context", &obligations[0], duplicate_source),
        (
            "wrong endpoint context",
            &obligations[0],
            duplicate_endpoint,
        ),
        ("wrong trace context", &obligations[0], duplicate_trace),
    ] {
        assert!(
            super::validate_duplicate_issue(&report.root, obligation, &issue).is_err(),
            "duplicate validator accepted {name}"
        );
    }
}

#[test]
fn adapter_rejects_wrong_count_and_reordered_empty_root_reports_atomically() {
    let root_function = function(90);
    let sink_function = exact_function(91);
    let facts = sink_artifact(root_function, sink_function);
    let first_request = InterpretationRoot {
        function: root_function,
        path: String::from("fixture::first_root"),
        kind: ReportRootKind::Generic,
    };
    let second_request = InterpretationRoot {
        function: function(92),
        path: String::from("fixture::second_root"),
        kind: ReportRootKind::Concrete,
    };
    let mut config = SniffTestConfig::default();
    config.panics.panic_sink_namespaces =
        PathPatterns::new(vec![String::from("fixture::sink")]).unwrap();
    let report = evaluate_typed_panic_call_with_dependencies(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        [],
        &[],
        &first_request,
        &config,
    )
    .expect("sink projection fixture evaluates");
    let first = empty_report(report.clone(), &first_request);
    let second = empty_report(report, &second_request);
    let roots = [first_request, second_request];

    let wrong_count_sources = CountingSources::default();
    assert!(
        adapt_typed_panic_call_reports(&wrong_count_sources, vec![first.clone()], &roots, false,)
            .is_err()
    );
    assert_eq!(wrong_count_sources.calls.get(), 0);

    let reordered_sources = CountingSources::default();
    assert!(
        adapt_typed_panic_call_reports(&reordered_sources, vec![second, first], &roots, false,)
            .is_err()
    );
    assert_eq!(reordered_sources.calls.get(), 0);
}

#[test]
fn unsatisfied_sink_projects_presentation_and_semantic_source_roles() {
    let root_function = function(1);
    let sink_function = exact_function(2);
    let facts = sink_artifact(root_function, sink_function);
    let mut config = SniffTestConfig::default();
    config.panics.panic_sink_namespaces =
        PathPatterns::new(vec![String::from("fixture::sink")]).unwrap();

    let requested_root = root(root_function);
    let report = evaluate_typed_panic_call_with_dependencies(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        [],
        &[],
        &requested_root,
        &config,
    )
    .expect("permanent panic call evaluation succeeds");

    assert_eq!(report.function, root_function);
    assert_eq!(report.issues.len(), 1);
    let issue = &report.issues[0];
    assert_eq!(issue.root, report.root);
    assert!(matches!(
        issue.kind,
        super::TypedPanicCallIssueKind::Unsatisfied {
            boundary: super::PanicCallBoundaryKind::PanicSink,
        }
    ));
    assert_eq!(issue.function, root_function);
    assert_eq!(issue.function_path, "fixture::root");
    assert_eq!(issue.target.function, Some(sink_function));
    assert_eq!(issue.target.path, "fixture::sink");
    assert_eq!(issue.source_range.as_ref().unwrap().byte_start, 20);
    assert_eq!(
        issue
            .trace
            .steps()
            .last()
            .unwrap()
            .source_key()
            .unwrap()
            .byte_start(),
        30
    );
    assert!(issue.missing_requirements.is_empty());
    assert!(issue.requirements.is_empty());

    let findings = adapt_typed_panic_call_reports(
        &NoSources,
        vec![report],
        std::slice::from_ref(&requested_root),
        false,
    )
    .expect("typed call report adapts through the legacy boundary");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].kind, FindingKind::PanicInvocation);
    assert_eq!(findings[0].target.as_deref(), Some("fixture::sink"));
    assert_eq!(findings[0].reason, "panic sink fixture::sink");
    assert_eq!(
        findings[0].trace,
        [
            String::from("fixture::root --macro-expansion-> macro fixture::call_macro"),
            String::from("macro fixture::call_macro --direct-call-> fixture::sink"),
        ]
    );

    let sources = FixtureSources {
        root: root_function,
        file: SourceFileIr {
            id: SourceFileId::new("fixture-file"),
            filename: String::from("src/lib.rs"),
            content_hash: String::from("sha256:typed-panic-call-fixture"),
            byte_len: 128,
        },
    };
    let legacy = legacy_sink_artifact(root_function, sink_function);
    let legacy_report = interpret(&legacy, std::slice::from_ref(&requested_root), &config);
    assert_eq!(legacy_report[0].findings.len(), 1);
    for show_full_stack_trace in [false, true] {
        let expected = adapt_typed_panic_call_finding(
            &sources,
            &requested_root,
            &legacy_report[0].findings[0],
            show_full_stack_trace,
        );
        let actual = adapt_typed_panic_call_reports(
            &sources,
            vec![
                evaluate_typed_panic_call_with_dependencies(
                    TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
                    [],
                    &[],
                    &requested_root,
                    &config,
                )
                .expect("permanent panic call evaluation succeeds"),
            ],
            std::slice::from_ref(&requested_root),
            show_full_stack_trace,
        )
        .expect("typed call report adapts through the legacy boundary");
        assert_eq!(actual, [expected]);
    }
}

#[test]
fn nested_macro_sink_projects_followed_and_terminal_calls_with_legacy_parity() {
    let root_function = function(50);
    let helper_function = exact_function(51);
    let sink_function = exact_function(52);
    let facts = nested_sink_artifact(root_function, helper_function, sink_function);
    let legacy = legacy_nested_sink_artifact(root_function, helper_function, sink_function);
    let requested_root = root(root_function);
    let mut config = SniffTestConfig::default();
    config.panics.panic_sink_namespaces =
        PathPatterns::new(vec![String::from("fixture::sink")]).unwrap();

    let report = evaluate_typed_panic_call_with_dependencies(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        [],
        &[],
        &requested_root,
        &config,
    )
    .expect("nested sink evaluation succeeds");
    assert_eq!(report.issues.len(), 1);
    let issue = &report.issues[0];
    assert_eq!(issue.function, helper_function);
    assert_eq!(issue.function_path, "fixture::helper");
    assert_eq!(issue.target.function, Some(sink_function));
    assert_eq!(issue.source_range, Some(range(60, 65)));
    let steps = issue.trace.steps();
    assert_eq!(steps.len(), 5);
    let PanicCallSemanticTraceStepKind::FollowedCall(followed) = steps[2].kind() else {
        panic!("the third semantic step must enter the helper body")
    };
    assert_eq!(followed.occurrence_data().key().local_id(), 6);
    assert_eq!(steps[2].owner().data().key(), &key(root_function));
    assert_eq!(
        steps[2].edge(),
        PanicCallSemanticEdge::Call(CallKind::DirectCall)
    );
    assert_eq!(
        steps[2].source_key(),
        Some(&SourceAnchorKey::new("fixture-file", 30, 35))
    );
    assert!(matches!(
        steps[4].kind(),
        PanicCallSemanticTraceStepKind::TerminalCall
    ));
    assert_eq!(steps[4].owner().data().key(), &key(helper_function));
    assert_eq!(
        steps[4].edge(),
        PanicCallSemanticEdge::Call(CallKind::DirectCall)
    );
    assert_eq!(
        steps[4].source_key(),
        Some(&SourceAnchorKey::new("fixture-file", 70, 75))
    );

    let sources = FixtureSources {
        root: root_function,
        file: SourceFileIr {
            id: SourceFileId::new("fixture-file"),
            filename: String::from("src/lib.rs"),
            content_hash: String::from("sha256:typed-panic-call-fixture"),
            byte_len: 128,
        },
    };
    let legacy_report = interpret(&legacy, std::slice::from_ref(&requested_root), &config);
    assert_eq!(legacy_report[0].findings.len(), 1);
    for show_full_stack_trace in [false, true] {
        let expected = adapt_typed_panic_call_finding(
            &sources,
            &requested_root,
            &legacy_report[0].findings[0],
            show_full_stack_trace,
        );
        let actual = adapt_typed_panic_call_reports(
            &sources,
            vec![report.clone()],
            std::slice::from_ref(&requested_root),
            show_full_stack_trace,
        )
        .expect("nested sink report adapts through the legacy boundary");
        assert_eq!(actual, [expected]);
        assert_eq!(
            actual[0].trace,
            [
                String::from(
                    "bytes 20..25: fixture::root --macro-expansion-> macro fixture::outer"
                ),
                String::from(
                    "bytes 26..29: macro fixture::outer --macro-expansion-> macro fixture::inner"
                ),
                String::from("bytes 30..35: macro fixture::inner --direct-call-> fixture::helper"),
                String::from(
                    "bytes 60..65: fixture::helper --macro-expansion-> macro fixture::terminal_macro"
                ),
                String::from(
                    "bytes 70..75: macro fixture::terminal_macro --direct-call-> fixture::sink"
                ),
            ]
        );
    }
}

#[test]
fn trusted_boundary_without_a_contract_emits_no_call_finding() {
    let root_function = function(30);
    let trusted_function = exact_function(31);
    let facts = sink_artifact(root_function, trusted_function);
    let legacy = legacy_sink_artifact(root_function, trusted_function);
    let requested_root = root(root_function);
    let mut config = SniffTestConfig::default();
    config.panics.trusted_panic_boundary_namespaces =
        PathPatterns::new(vec![String::from("fixture::sink")]).unwrap();

    let report = evaluate_typed_panic_call_with_dependencies(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        [],
        &[],
        &requested_root,
        &config,
    )
    .expect("trusted boundary evaluation succeeds");
    assert!(report.issues.is_empty());
    let legacy_report = interpret(&legacy, std::slice::from_ref(&requested_root), &config);
    assert!(legacy_report[0].findings.is_empty());

    for show_full_stack_trace in [false, true] {
        let actual = adapt_typed_panic_call_reports(
            &NoSources,
            vec![report.clone()],
            std::slice::from_ref(&requested_root),
            show_full_stack_trace,
        )
        .expect("empty trusted report adapts through the legacy boundary");
        assert!(actual.is_empty());
    }
}

#[test]
fn targetless_opaque_call_normalizes_only_its_report_presentation() {
    const RAW_DESCRIPTION: &str = "rustc-specific unsafe fn pointer spelling";
    const SEMANTIC_DESCRIPTION: &str = "indirect call through a function pointer";

    let root_function = function(40);
    let facts = targetless_opaque_artifact(root_function, false);
    let legacy = legacy_targetless_opaque_artifact(root_function, false);
    let requested_root = root(root_function);
    let report = evaluate_typed_panic_call_with_dependencies(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        [],
        &[],
        &requested_root,
        &SniffTestConfig::default(),
    )
    .expect("targetless opaque evaluation succeeds");

    assert_eq!(report.issues.len(), 1);
    let issue = &report.issues[0];
    assert_eq!(issue.target.function, None);
    assert_eq!(issue.target.path, SEMANTIC_DESCRIPTION);
    assert_eq!(issue.source_range, Some(range(20, 25)));
    assert_eq!(
        issue
            .trace
            .terminal()
            .presentation()
            .raw_opaque_description(),
        Some(RAW_DESCRIPTION)
    );
    assert_eq!(
        issue.trace.terminal().presentation().semantic_description(),
        Some(SEMANTIC_DESCRIPTION)
    );
    assert_eq!(
        issue.trace.terminal().boundary_description(),
        Some(SEMANTIC_DESCRIPTION)
    );
    assert_eq!(
        issue.trace.steps().last().unwrap().source_key(),
        Some(&SourceAnchorKey::new("fixture-file", 30, 35))
    );

    let sources = FixtureSources {
        root: root_function,
        file: SourceFileIr {
            id: SourceFileId::new("fixture-file"),
            filename: String::from("src/lib.rs"),
            content_hash: String::from("sha256:typed-panic-call-fixture"),
            byte_len: 128,
        },
    };
    let legacy_report = interpret(
        &legacy,
        std::slice::from_ref(&requested_root),
        &SniffTestConfig::default(),
    );
    assert_eq!(legacy_report[0].findings.len(), 1);
    for show_full_stack_trace in [false, true] {
        let expected = adapt_typed_panic_call_finding(
            &sources,
            &requested_root,
            &legacy_report[0].findings[0],
            show_full_stack_trace,
        );
        let actual = adapt_typed_panic_call_reports(
            &sources,
            vec![report.clone()],
            std::slice::from_ref(&requested_root),
            show_full_stack_trace,
        )
        .expect("targetless opaque report adapts through the legacy boundary");
        assert_eq!(actual, [expected]);
        assert_eq!(actual[0].kind, FindingKind::IndirectCallBoundary);
        assert_eq!(actual[0].target, None);
        assert_eq!(
            actual[0].reason,
            "indirect call through a function pointer cannot be verified"
        );
    }
}

#[test]
fn targetless_unsafe_opaque_call_uses_the_unsafe_semantic_description() {
    const RAW_DESCRIPTION: &str = "rustc-specific unsafe fn pointer spelling";
    const SEMANTIC_DESCRIPTION: &str = "indirect call through an unsafe function pointer";

    let root_function = function(41);
    let facts = targetless_opaque_artifact(root_function, true);
    let legacy = legacy_targetless_opaque_artifact(root_function, true);
    let requested_root = root(root_function);
    let report = evaluate_typed_panic_call_with_dependencies(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        [],
        &[],
        &requested_root,
        &SniffTestConfig::default(),
    )
    .expect("unsafe targetless opaque evaluation succeeds");
    assert_eq!(report.issues.len(), 1);
    assert_eq!(report.issues[0].target.function, None);
    assert_eq!(report.issues[0].target.path, SEMANTIC_DESCRIPTION);
    assert_eq!(
        report.issues[0]
            .trace
            .terminal()
            .presentation()
            .raw_opaque_description(),
        Some(RAW_DESCRIPTION)
    );
    assert_eq!(
        report.issues[0].trace.terminal().boundary_description(),
        Some(SEMANTIC_DESCRIPTION)
    );

    let sources = FixtureSources {
        root: root_function,
        file: SourceFileIr {
            id: SourceFileId::new("fixture-file"),
            filename: String::from("src/lib.rs"),
            content_hash: String::from("sha256:typed-panic-call-fixture"),
            byte_len: 128,
        },
    };
    let legacy_report = interpret(
        &legacy,
        std::slice::from_ref(&requested_root),
        &SniffTestConfig::default(),
    );
    let legacy_panic = legacy_report[0]
        .findings
        .iter()
        .find(|finding| {
            matches!(
                finding.kind,
                InterpretedFindingKind::OpaquePanicBoundary { .. }
            )
        })
        .expect("legacy interpretation emits the unsafe opaque panic boundary");
    for show_full_stack_trace in [false, true] {
        let expected = adapt_typed_panic_call_finding(
            &sources,
            &requested_root,
            legacy_panic,
            show_full_stack_trace,
        );
        let actual = adapt_typed_panic_call_reports(
            &sources,
            vec![report.clone()],
            std::slice::from_ref(&requested_root),
            show_full_stack_trace,
        )
        .expect("unsafe targetless report adapts through the legacy boundary");
        assert_eq!(actual, [expected]);
        assert_eq!(actual[0].target, None);
        assert_eq!(
            actual[0].reason,
            "indirect call through an unsafe function pointer cannot be verified"
        );
    }
}

#[test]
fn late_cross_root_issue_rejects_the_whole_adapter_batch_before_projection() {
    let root_function = function(60);
    let sink_function = exact_function(61);
    let facts = sink_artifact(root_function, sink_function);
    let requested_root = root(root_function);
    let mut config = SniffTestConfig::default();
    config.panics.panic_sink_namespaces =
        PathPatterns::new(vec![String::from("fixture::sink")]).unwrap();
    let report = evaluate_typed_panic_call_with_dependencies(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        [],
        &[],
        &requested_root,
        &config,
    )
    .expect("sink evaluation succeeds");
    let mut hostile = report.clone();
    let hostile_issue = hostile
        .issues
        .first_mut()
        .expect("sink fixture emits one issue");
    assert!(matches!(
        hostile_issue.kind,
        super::TypedPanicCallIssueKind::Unsatisfied { .. }
    ));
    hostile_issue.root.domain = DomainId::new("hostile.panic").unwrap();
    let sources = CountingSources::default();
    let error = adapt_typed_panic_call_reports(
        &sources,
        vec![report, hostile],
        &[requested_root.clone(), requested_root],
        false,
    )
    .expect_err("a late cross-root issue must reject the complete report batch");

    assert!(error.to_string().contains("issue report"));
    assert_eq!(sources.calls.get(), 0);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one parity test freezes duplicate provenance, anchors, sharing, and full Finding equality"
)]
fn fully_satisfied_duplicate_groups_share_one_projected_witness() {
    let root_function = function(10);
    let documented_function = exact_function(11);
    let facts = documented_duplicate_artifact(root_function, documented_function);
    let legacy = legacy_documented_duplicate_artifact(root_function, documented_function);
    let requested_root = root(root_function);

    let report = evaluate_typed_panic_call_with_dependencies(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        [],
        &[],
        &requested_root,
        &SniffTestConfig::default(),
    )
    .expect("duplicate contract evaluation succeeds");

    assert_eq!(report.issues.len(), 2);
    assert!(
        report
            .issues
            .iter()
            .all(|issue| matches!(issue.kind, super::TypedPanicCallIssueKind::Duplicate { .. }))
    );
    assert!(
        report
            .issues
            .iter()
            .all(|issue| issue.missing_requirements.is_empty())
    );
    assert_eq!(report.issues[0].requirements.len(), 2);
    assert_eq!(report.issues[1].requirements.len(), 2);
    assert_eq!(report.issues[0].source_range, Some(range(50, 55)));
    assert_eq!(report.issues[1].source_range, Some(range(50, 55)));
    let duplicate_groups = report
        .issues
        .iter()
        .map(|issue| {
            let super::TypedPanicCallIssueKind::Duplicate { normalized_name } = &issue.kind else {
                unreachable!("the fixture emits only duplicate issues")
            };
            (
                normalized_name.as_str(),
                issue
                    .requirements
                    .iter()
                    .map(|requirement| {
                        (
                            requirement.name.as_str(),
                            requirement.source_range.as_ref().unwrap().byte_start,
                        )
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        duplicate_groups,
        [
            (
                "index in bounds",
                vec![("Index_In-Bounds", 60), ("index-in_bounds", 70)],
            ),
            ("ready", vec![("Ready", 80), ("READY", 90)]),
        ]
    );
    assert!(Arc::ptr_eq(
        &report.issues[0].trace,
        &report.issues[1].trace
    ));

    let sources = FixtureSources {
        root: root_function,
        file: SourceFileIr {
            id: SourceFileId::new("fixture-file"),
            filename: String::from("src/lib.rs"),
            content_hash: String::from("sha256:typed-panic-call-fixture"),
            byte_len: 128,
        },
    };
    let legacy_report = interpret(
        &legacy,
        std::slice::from_ref(&requested_root),
        &SniffTestConfig::default(),
    );
    assert_eq!(legacy_report[0].findings.len(), 2);
    for show_full_stack_trace in [false, true] {
        let expected = legacy_report[0]
            .findings
            .iter()
            .map(|finding| {
                adapt_typed_panic_call_finding(
                    &sources,
                    &requested_root,
                    finding,
                    show_full_stack_trace,
                )
            })
            .collect::<Vec<_>>();
        let actual = adapt_typed_panic_call_reports(
            &sources,
            vec![report.clone()],
            std::slice::from_ref(&requested_root),
            show_full_stack_trace,
        )
        .expect("duplicate report adapts through the legacy boundary");
        assert_eq!(actual, expected);
        assert_eq!(actual[0].span.as_deref(), Some("bytes 60..65"));
        assert_eq!(actual[1].span.as_deref(), Some("bytes 80..85"));
    }
}
