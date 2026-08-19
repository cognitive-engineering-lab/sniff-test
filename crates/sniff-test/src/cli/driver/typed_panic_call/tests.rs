use std::cell::Cell;
use std::sync::Arc;

use crate::analysis::collected::{
    CollectedArtifact, CollectedArtifactInput, CollectedCallMacroFrame, CollectedCallOccurrence,
    CollectedCallSite, CollectedCallSourceAnchor, CollectedCallTarget,
    CollectedEffectMarkerCandidate, CollectedEffectSite, CollectedEffectSourceAnchor,
    CollectedFunctionBody, CollectedMarkerCallCandidate, CollectedMarkerOccurrence,
    CollectedMirAssert, CollectedPanicContract, CollectedProgram,
};
use crate::analysis::facts::collection::collect_artifact_facts;
use crate::analysis::facts::encoded::{EntityRef, TableKind};
use crate::analysis::facts::evaluation::DomainId;
use crate::analysis::facts::human::EvidenceClaimSelector;
use crate::analysis::facts::human::markers::{
    CallOccurrenceHasMarkerClaimCandidate, EffectSiteHasMarkerClaimCandidate, MarkerClaimEntity,
    MarkerClaimKey, MarkerOccurrenceEntity, MarkerOccurrenceKey,
};
use crate::analysis::facts::panic::contracts::{PanicContractFact, PanicRequirement};
use crate::analysis::facts::panic::model::MirAssertKind;
use crate::analysis::facts::program::topology::{
    CallAttributionRole, CallKind, CallMacroExpansionEntity, CallMacroExpansionKey,
    CallOccurrenceEntity, CallOccurrenceKey, CallSiteEntity, CallSiteKey, CallSourceAnchorRole,
    CallTargetRole, CallableEntity, SafetyEffectGroupEntity, SafetyEffectGroupKey,
};
use crate::analysis::facts::program::{
    EffectSiteEntity, EffectSiteKey, EffectSourceAnchorRole, FunctionBodyProvenance,
    FunctionEntity, FunctionKey, SourceAnchorEntity, SourceAnchorKey, SourceFileEntity,
};
use crate::analysis::facts::schema::{PassId, RowSchema, SchemaId};
use crate::analysis::facts::workspace::ScopedEntityRef;
use crate::analysis::interpret::{InterpretationRoot, InterpretedFindingKind, interpret};
use crate::analysis::ir::{
    ArtifactAnalysisIr, CallEdgeIr, CallEdgeKindIr, CallId, CallSiteId, CallTargetIr,
    CallableAttributionIr, CompilerAssertKind, ContractRequirementIr, EffectFactIr, EffectId,
    EffectKindIr, FunctionAttributesIr, FunctionBodyIr, FunctionBodyProvenanceIr,
    FunctionContractsIr, FunctionId, FunctionTargetIr, MacroExpansionFrameIr, MarkerId, MarkerIr,
    MarkerKindIr, MarkerProbingIr, MarkerSatisfactionIr, MarkerTargetIr, RawContractIr,
    SafetyEffectGroupId, SourceFileId, SourceFileIr, SourceRangeIr, StableInstanceHash,
};
use crate::cli::driver::interpretation::{
    FindingSources, adapt_typed_panic_authority_batch, adapt_typed_panic_incomplete_finding,
    adapt_typed_panic_reports,
};
use crate::cli::findings::FindingKind;
use crate::config::SniffTestConfig;
use crate::contracts::ContractDocOverrides;
use crate::namespace::{StableDefPathHash, StableExpansionHash};
use crate::path_patterns::PathPatterns;
use crate::report_roots::ReportRootKind;
use reachability::MirBodyLocation;
use rustc_span::{BytePos, Span};

use super::super::typed_panic::{
    TypedPanicLocalArtifact, compiler_assert_oracle_registry_for_test,
};
use super::{
    AmbiguityProjectionCorruption, PanicCallSemanticEdge, PanicCallSemanticTraceStepKind,
    adapt_typed_panic_ambiguity_reports, adapt_typed_panic_call_completeness_reports,
    adapt_typed_panic_call_finding, adapt_typed_panic_call_reports,
    adapt_typed_panic_root_contract_reports, evaluate_typed_panic_call_with_ambiguity_corruption,
    evaluate_typed_panic_call_with_completeness, evaluate_typed_panic_call_with_dependencies,
    evaluate_typed_panic_call_with_projection_fixture,
};

const LOCAL_CRATE: u64 = 1;

#[test]
fn complete_traversal_retains_positive_summary_without_a_completeness_finding() {
    let root_function = function(100);
    let facts = sink_artifact(root_function, exact_function(101));
    let requested_root = root(root_function);

    let (call, completeness, fixture) = evaluate_typed_panic_call_with_projection_fixture(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        [],
        &[],
        &requested_root,
        &SniffTestConfig::default(),
    )
    .expect("the shared typed panic-call evaluation succeeds");

    assert_eq!(call.root, completeness.root);
    assert_eq!(completeness.function, root_function);
    assert_eq!(completeness.path, requested_root.path);
    assert_eq!(completeness.kind, requested_root.kind);
    assert_eq!(completeness.expanded_bodies, 1);
    assert!(completeness.issues.is_empty());
    assert!(fixture.incomplete.is_empty());
    assert!(matches!(
        fixture.completeness.as_slice(),
        [summary] if summary.data.complete() && summary.data.reasons().is_empty()
    ));
    assert!(
        adapt_typed_panic_call_completeness_reports(
            &NoSources,
            vec![completeness],
            std::slice::from_ref(&requested_root),
            false,
        )
        .expect("a complete summary adapts")
        .is_empty()
    );
}

#[test]
fn node_limit_completeness_has_exact_legacy_finding_parity() {
    let root_function = function(102);
    let target_function = exact_function(103);
    let facts = sink_artifact(root_function, target_function);
    let legacy = legacy_sink_artifact(root_function, target_function);
    let requested_root = root(root_function);
    let mut config = SniffTestConfig::default();
    config.analysis.node_limit = 0;
    let sources = FixtureSources {
        root: root_function,
        file: SourceFileIr {
            id: SourceFileId::new("fixture-file"),
            filename: String::from("src/lib.rs"),
            content_hash: String::from("sha256:typed-panic-call-fixture"),
            byte_len: 128,
        },
    };

    let (_, completeness) = evaluate_typed_panic_call_with_completeness(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        [],
        &[],
        &requested_root,
        &config,
    )
    .expect("the limited shared evaluator succeeds");
    assert_eq!(completeness.expanded_bodies, 0);
    assert!(matches!(
        completeness.issues.as_slice(),
        [super::TypedPanicCompletenessIssueReport {
            reason: crate::analysis::interpret::IncompleteReason::NodeLimit { limit: 0 },
            ..
        }]
    ));

    let legacy_report = interpret(&legacy, std::slice::from_ref(&requested_root), &config);
    let [legacy_reason] = legacy_report[0].completeness.panic.reasons.as_slice() else {
        panic!("legacy analysis must retain one node-limit reason");
    };
    for show_full_stack_trace in [false, true] {
        let expected = adapt_typed_panic_incomplete_finding(
            &sources,
            &requested_root,
            legacy_reason.clone(),
            show_full_stack_trace,
        );
        let actual = adapt_typed_panic_call_completeness_reports(
            &sources,
            vec![completeness.clone()],
            std::slice::from_ref(&requested_root),
            show_full_stack_trace,
        )
        .expect("typed completeness adapts through the legacy report boundary");
        assert_eq!(actual, [expected]);
        assert_eq!(actual[0].kind, FindingKind::PanicAnalysisIncomplete);
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one parity test freezes all source, macro, and occurrence identity traps"
)]
fn managed_missing_body_completeness_has_exact_legacy_parity_and_source_degradation() {
    let root_function = function(104);
    let helper_function = exact_function(105);
    let missing_function = exact_function(106);
    let facts = nested_artifact(root_function, helper_function, missing_function, true);
    let legacy = legacy_nested_artifact(root_function, helper_function, missing_function, true);
    let requested_root = root(root_function);

    let (_, completeness) = evaluate_typed_panic_call_with_completeness(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        [],
        &[],
        &requested_root,
        &SniffTestConfig::default(),
    )
    .expect("the shared evaluator projects the reached missing body");
    assert_eq!(completeness.expanded_bodies, 2);
    let [issue] = completeness.issues.as_slice() else {
        panic!("one missing managed body must produce one report issue");
    };
    let crate::analysis::interpret::IncompleteReason::MissingBody {
        function,
        path,
        source_range,
        trace,
    } = &issue.reason
    else {
        panic!("the issue must retain a missing-body reason");
    };
    assert_eq!(*function, missing_function);
    assert_eq!(path, "fixture::sink");
    assert_eq!(*source_range, Some(range(60, 65)));
    assert_eq!(trace.steps.len(), 5);
    assert_eq!(trace.steps[3].call, CallId::new(7));
    assert_eq!(trace.steps[4].call, CallId::new(7));
    assert_eq!(
        trace.steps[4].kind,
        crate::analysis::interpret::InterpretedTraceStepKind::Reachability(
            CallEdgeKindIr::DirectCall
        )
    );
    assert_eq!(trace.steps[4].source_range, Some(range(70, 75)));
    assert_eq!(trace.steps[4].target, Some(missing_function));
    assert_eq!(trace.steps[4].target_path.as_deref(), Some("fixture::sink"));

    let legacy_report = interpret(
        &legacy,
        std::slice::from_ref(&requested_root),
        &SniffTestConfig::default(),
    );
    let [legacy_reason] = legacy_report[0].completeness.panic.reasons.as_slice() else {
        panic!("legacy analysis must retain the same missing body");
    };
    assert_eq!(&issue.reason, legacy_reason);

    let sources = FixtureSources {
        root: root_function,
        file: SourceFileIr {
            id: SourceFileId::new("fixture-file"),
            filename: String::from("src/lib.rs"),
            content_hash: String::from("sha256:typed-panic-call-fixture"),
            byte_len: 128,
        },
    };
    for show_full_stack_trace in [false, true] {
        let expected = adapt_typed_panic_incomplete_finding(
            &sources,
            &requested_root,
            legacy_reason.clone(),
            show_full_stack_trace,
        );
        let actual = adapt_typed_panic_call_completeness_reports(
            &sources,
            vec![completeness.clone()],
            std::slice::from_ref(&requested_root),
            show_full_stack_trace,
        )
        .expect("typed missing-body report adapts");
        assert_eq!(actual, [expected]);

        let expected_degraded = adapt_typed_panic_incomplete_finding(
            &UnavailableSources,
            &requested_root,
            legacy_reason.clone(),
            show_full_stack_trace,
        );
        let actual_degraded = adapt_typed_panic_call_completeness_reports(
            &UnavailableSources,
            vec![completeness.clone()],
            std::slice::from_ref(&requested_root),
            show_full_stack_trace,
        )
        .expect("typed missing-body report degrades unavailable sources");
        assert_eq!(actual_degraded, [expected_degraded]);
        assert!(actual_degraded[0].span.is_none());
        assert!(actual_degraded[0]
            .diagnostic
            .messages
            .iter()
            .any(|message| matches!(message, crate::cli::findings::DiagnosticMessage::Note(note) if note.contains("fixture source unavailable"))));
    }
}

#[test]
fn mixed_completeness_reorders_context_sorted_issues_to_summary_traversal_order() {
    let root_function = function(107);
    let missing_function = exact_function(108);
    let deferred_function = exact_function(109);
    let facts = mixed_completeness_artifact(root_function, missing_function, deferred_function);
    let legacy =
        legacy_mixed_completeness_artifact(root_function, missing_function, deferred_function);
    let requested_root = root(root_function);
    let mut config = SniffTestConfig::default();
    config.analysis.node_limit = 1;

    let (call_report, completeness, fixture) = evaluate_typed_panic_call_with_projection_fixture(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        [],
        &[],
        &requested_root,
        &config,
    )
    .expect("mixed completeness evaluation succeeds");
    assert_eq!(call_report.root, completeness.root);
    assert!(call_report.issues.is_empty());
    let [summary] = fixture.completeness.as_slice() else {
        panic!("one positive completeness summary must be retained");
    };
    assert_eq!(summary.data.expanded_bodies(), 1);
    assert!(
        matches!(
            summary.data.reasons(),
            [first, second]
                if matches!(first.reason(), crate::analysis::facts::panic::PanicIncompleteReason::MissingManagedBody { .. })
                    && matches!(second.reason(), crate::analysis::facts::panic::PanicIncompleteReason::NodeLimit { limit: 1 })
        ),
        "unexpected summary reasons: {:?}",
        summary.data.reasons()
    );
    assert!(matches!(
        fixture.incomplete.as_slice(),
        [first, second]
            if matches!(first.data.reason(), crate::analysis::facts::panic::PanicIncompleteReason::NodeLimit { limit: 1 })
                && matches!(second.data.reason(), crate::analysis::facts::panic::PanicIncompleteReason::MissingManagedBody { .. })
    ));
    assert!(matches!(
        completeness.issues.as_slice(),
        [first, second]
            if matches!(first.reason, crate::analysis::interpret::IncompleteReason::MissingBody { .. })
                && matches!(second.reason, crate::analysis::interpret::IncompleteReason::NodeLimit { limit: 1 })
    ));

    let legacy_report = interpret(&legacy, std::slice::from_ref(&requested_root), &config);
    let legacy_reasons = &legacy_report[0].completeness.panic.reasons;
    assert_eq!(
        completeness
            .issues
            .iter()
            .map(|issue| &issue.reason)
            .collect::<Vec<_>>(),
        legacy_reasons.iter().collect::<Vec<_>>()
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
    for show_full_stack_trace in [false, true] {
        let expected = legacy_reasons
            .iter()
            .cloned()
            .map(|reason| {
                adapt_typed_panic_incomplete_finding(
                    &sources,
                    &requested_root,
                    reason,
                    show_full_stack_trace,
                )
            })
            .collect::<Vec<_>>();
        let actual = adapt_typed_panic_call_completeness_reports(
            &sources,
            vec![completeness.clone()],
            std::slice::from_ref(&requested_root),
            show_full_stack_trace,
        )
        .expect("mixed completeness reports adapt in summary order");
        assert_eq!(actual, expected);
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the hostile matrix freezes every independent raw-row join invariant"
)]
fn completeness_projection_rejects_hostile_summary_issue_and_context_joins() {
    let root_function = function(110);
    let missing_function = exact_function(111);
    let deferred_function = exact_function(112);
    let facts = mixed_completeness_artifact(root_function, missing_function, deferred_function);
    let requested_root = root(root_function);
    let mut config = SniffTestConfig::default();
    config.analysis.node_limit = 1;
    let (call, completeness, fixture) = evaluate_typed_panic_call_with_projection_fixture(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        [],
        &[],
        &requested_root,
        &config,
    )
    .expect("hostile projection fixture evaluates once");
    let project = |summaries, issues| {
        super::project_completeness_report(
            &fixture.inputs,
            completeness.presentation_range.clone(),
            &requested_root,
            &call.root,
            summaries,
            issues,
        )
    };
    project(fixture.completeness.clone(), fixture.incomplete.clone())
        .expect("the unmodified raw join is valid");

    let mut duplicate_summary = fixture.completeness.clone();
    duplicate_summary.push(duplicate_summary[0].clone());
    let mut wrong_summary_root = fixture.completeness.clone();
    wrong_summary_root[0].root.domain = DomainId::new("hostile.panic").unwrap();
    let mut wrong_summary_producer = fixture.completeness.clone();
    wrong_summary_producer[0].producer = PassId::new("hostile.producer").unwrap();
    let mut wrong_body_count = fixture.completeness.clone();
    wrong_body_count[0].data = crate::analysis::facts::panic::PanicCompletenessOutcome::new(
        wrong_body_count[0].data.expanded_bodies() + 1,
        wrong_body_count[0].data.reasons().to_vec(),
    );
    let mut wrong_issue_producer = fixture.incomplete.clone();
    wrong_issue_producer[0].producer = PassId::new("hostile.producer").unwrap();
    let mut wrong_issue_root = fixture.incomplete.clone();
    wrong_issue_root[0].context.root.domain = DomainId::new("hostile.panic").unwrap();
    let mut wrong_issue_source = fixture.incomplete.clone();
    let missing_issue = wrong_issue_source
        .iter_mut()
        .find(|issue| {
            matches!(
                issue.data.reason(),
                crate::analysis::facts::panic::PanicIncompleteReason::MissingManagedBody { .. }
            )
        })
        .expect("mixed fixture contains a missing issue");
    missing_issue.context.source = None;
    let mut wrong_issue_endpoint = fixture.incomplete.clone();
    wrong_issue_endpoint
        .iter_mut()
        .find(|issue| issue.context.endpoint.is_some())
        .expect("mixed fixture contains a missing issue")
        .context
        .endpoint = None;
    let mut wrong_issue_trace = fixture.incomplete.clone();
    wrong_issue_trace
        .iter_mut()
        .find(|issue| issue.context.trace.is_some())
        .expect("mixed fixture contains a missing issue")
        .context
        .trace = None;
    let node_order = fixture.completeness[0]
        .data
        .reasons()
        .iter()
        .find(|reason| {
            matches!(
                reason.reason(),
                crate::analysis::facts::panic::PanicIncompleteReason::NodeLimit { .. }
            )
        })
        .expect("mixed fixture contains a node-limit reason")
        .traversal_order();
    let changed_node =
        crate::analysis::facts::panic::PanicCompletenessReason::node_limit(node_order, 2);
    let mut wrong_issue_data = fixture.incomplete.clone();
    wrong_issue_data
        .iter_mut()
        .find(|issue| issue.data.traversal_order() == node_order)
        .expect("mixed fixture contains a node-limit issue")
        .data = crate::analysis::facts::panic::PanicAnalysisIncompleteIssue::from_reason(
        changed_node.clone(),
    );
    let mut wrong_summary_reason = fixture.completeness.clone();
    let expanded = wrong_summary_reason[0].data.expanded_bodies();
    let mut reasons = wrong_summary_reason[0].data.reasons().to_vec();
    *reasons
        .iter_mut()
        .find(|reason| reason.traversal_order() == node_order)
        .expect("mixed summary contains the node-limit reason") = changed_node;
    wrong_summary_reason[0].data =
        crate::analysis::facts::panic::PanicCompletenessOutcome::new(expanded, reasons);
    let mut missing_issue_row = fixture.incomplete.clone();
    missing_issue_row.pop();
    let mut extra_issue_row = fixture.incomplete.clone();
    extra_issue_row.push(extra_issue_row[0].clone());
    let missing_context = fixture
        .incomplete
        .iter()
        .find(|issue| issue.context.source.is_some())
        .expect("the missing issue has full context")
        .context
        .clone();
    let mut polluted_node_context = fixture.incomplete.clone();
    polluted_node_context
        .iter_mut()
        .find(|issue| {
            matches!(
                issue.data.reason(),
                crate::analysis::facts::panic::PanicIncompleteReason::NodeLimit { .. }
            )
        })
        .expect("mixed fixture contains a node-limit issue")
        .context = missing_context;

    for (name, summaries, issues) in [
        ("missing summary", Vec::new(), fixture.incomplete.clone()),
        (
            "duplicate summary",
            duplicate_summary,
            fixture.incomplete.clone(),
        ),
        (
            "wrong summary root",
            wrong_summary_root,
            fixture.incomplete.clone(),
        ),
        (
            "wrong summary producer",
            wrong_summary_producer,
            fixture.incomplete.clone(),
        ),
        (
            "wrong body count",
            wrong_body_count,
            fixture.incomplete.clone(),
        ),
        (
            "wrong issue producer",
            fixture.completeness.clone(),
            wrong_issue_producer,
        ),
        (
            "wrong issue root",
            fixture.completeness.clone(),
            wrong_issue_root,
        ),
        (
            "wrong issue source context",
            fixture.completeness.clone(),
            wrong_issue_source,
        ),
        (
            "wrong issue endpoint context",
            fixture.completeness.clone(),
            wrong_issue_endpoint,
        ),
        (
            "wrong issue trace context",
            fixture.completeness.clone(),
            wrong_issue_trace,
        ),
        (
            "wrong issue data",
            fixture.completeness.clone(),
            wrong_issue_data,
        ),
        (
            "wrong summary reason data",
            wrong_summary_reason,
            fixture.incomplete.clone(),
        ),
        (
            "missing issue",
            fixture.completeness.clone(),
            missing_issue_row,
        ),
        (
            "extra orphan issue",
            fixture.completeness.clone(),
            extra_issue_row,
        ),
        (
            "polluted node-limit context",
            fixture.completeness.clone(),
            polluted_node_context,
        ),
    ] {
        assert!(project(summaries, issues).is_err(), "accepted {name}");
    }

    let [summary] = fixture.completeness.as_slice() else {
        unreachable!("the fixture retains one summary")
    };
    let missing = summary
        .data
        .reasons()
        .iter()
        .find(|reason| {
            matches!(
                reason.reason(),
                crate::analysis::facts::panic::PanicIncompleteReason::MissingManagedBody { .. }
            )
        })
        .expect("mixed fixture contains one missing reason");
    let crate::analysis::facts::panic::PanicIncompleteReason::MissingManagedBody {
        function,
        path,
        presentation_source,
        semantic_trace,
        relation_trace,
    } = missing.reason()
    else {
        unreachable!("the selected reason is missing-body")
    };

    let hostile_relation_reason =
        crate::analysis::facts::panic::PanicCompletenessReason::missing_managed_body(
            missing.traversal_order(),
            *function,
            path,
            presentation_source.clone(),
            semantic_trace.clone(),
            crate::analysis::facts::evaluation::RelationTrace::new(
                relation_trace.target().clone(),
                relation_trace.target().clone(),
                relation_trace.relations().to_vec(),
            ),
        );
    let relation_error = project_hostile_missing_reason(
        &fixture.inputs,
        completeness.presentation_range.clone(),
        &requested_root,
        &call.root,
        summary,
        &fixture.incomplete,
        missing.traversal_order(),
        &hostile_relation_reason,
    )
    .expect_err("a self-consistent issue with the wrong trace root must fail");
    assert!(relation_error.to_string().contains("trace starts"));

    let mut hostile_semantic_trace = semantic_trace.clone();
    let terminal = hostile_semantic_trace
        .last()
        .expect("the valid missing reason has a terminal semantic step");
    let hostile_terminal = crate::analysis::facts::panic::PanicCompletenessSemanticStep::new(
        terminal.caller(),
        terminal.caller_path(),
        terminal.call_local_id(),
        terminal.kind(),
        terminal.source().cloned(),
        Some(key(root_function)),
        Some(String::from("fixture::wrong-terminal")),
    );
    *hostile_semantic_trace
        .last_mut()
        .expect("the hostile trace retains a terminal slot") = hostile_terminal;
    let hostile_terminal_reason =
        crate::analysis::facts::panic::PanicCompletenessReason::missing_managed_body(
            missing.traversal_order(),
            *function,
            path,
            presentation_source.clone(),
            hostile_semantic_trace,
            relation_trace.clone(),
        );
    let terminal_error = project_hostile_missing_reason(
        &fixture.inputs,
        completeness.presentation_range.clone(),
        &requested_root,
        &call.root,
        summary,
        &fixture.incomplete,
        missing.traversal_order(),
        &hostile_terminal_reason,
    )
    .expect_err("a self-consistent issue with the wrong semantic terminal must fail");
    assert!(terminal_error.to_string().contains("terminal target"));
}

#[test]
fn completeness_adapter_preflights_the_entire_batch_before_source_resolution() {
    let first_function = function(113);
    let facts = sink_artifact(first_function, exact_function(114));
    let first_request = root(first_function);
    let (_, first) = evaluate_typed_panic_call_with_completeness(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        [],
        &[],
        &first_request,
        &SniffTestConfig::default(),
    )
    .expect("complete adapter fixture evaluates");
    let second_request = InterpretationRoot {
        function: function(115),
        path: String::from("fixture::second_root"),
        kind: ReportRootKind::Concrete,
    };
    let mut second = first.clone();
    second.function = second_request.function;
    second.path.clone_from(&second_request.path);
    second.kind = second_request.kind;
    let roots = [first_request.clone(), second_request];

    let wrong_count_sources = CountingSources::default();
    assert!(
        adapt_typed_panic_call_completeness_reports(
            &wrong_count_sources,
            vec![first.clone()],
            &roots,
            false,
        )
        .is_err()
    );
    assert_eq!(wrong_count_sources.calls.get(), 0);

    let reordered_sources = CountingSources::default();
    assert!(
        adapt_typed_panic_call_completeness_reports(
            &reordered_sources,
            vec![second, first],
            &roots,
            false,
        )
        .is_err()
    );
    assert_eq!(reordered_sources.calls.get(), 0);

    let mixed_facts =
        mixed_completeness_artifact(first_function, exact_function(116), exact_function(117));
    let mut limited = SniffTestConfig::default();
    limited.analysis.node_limit = 1;
    let (_, mixed) = evaluate_typed_panic_call_with_completeness(
        TypedPanicLocalArtifact::in_memory(&mixed_facts, LOCAL_CRATE),
        [],
        &[],
        &first_request,
        &limited,
    )
    .expect("mixed adapter fixture evaluates");
    let mut hostile = mixed.clone();
    hostile
        .issues
        .last_mut()
        .expect("mixed report has a late issue")
        .root
        .domain = DomainId::new("hostile.panic").unwrap();
    let late_sources = CountingSources::default();
    assert!(
        adapt_typed_panic_call_completeness_reports(
            &late_sources,
            vec![mixed, hostile],
            &[first_request.clone(), first_request],
            true,
        )
        .is_err()
    );
    assert_eq!(late_sources.calls.get(), 0);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one ordered fixture pins preparation metadata and all five sparse report lanes"
)]
fn ready_and_missing_roots_preserve_request_order_with_sparse_ready_lanes() {
    let root_function = function(118);
    let second_function = function(119);
    let facts = root_preparation_artifact(&[root_function, second_function]);
    let valid = root(root_function);
    let unknown = InterpretationRoot {
        function: function(120),
        path: String::from("fixture::unknown"),
        kind: ReportRootKind::Generic,
    };
    let second = InterpretationRoot {
        function: second_function,
        path: String::from("fixture::second"),
        kind: ReportRootKind::Concrete,
    };
    let requests = [valid.clone(), unknown.clone(), second.clone()];

    let batch = super::evaluate_typed_panic_call_roots(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        &[],
        Vec::new(),
        &[],
        &requests,
        &SniffTestConfig::default(),
    )
    .expect("a local missing root is retained as incomplete preparation evidence");

    let [ready, missing, later_ready] = batch.root_preparations.as_slice() else {
        panic!("three requests must produce three ordered preparation rows");
    };
    assert_eq!(ready.request_ordinal, 0);
    assert_eq!(ready.request, valid);
    assert_eq!(ready.requested_function, key(root_function));
    assert!(matches!(
        ready.outcome,
        super::TypedPanicRootPreparationOutcome::Evaluatable {
            report_index: 0,
            ..
        }
    ));
    let super::TypedPanicRootPreparationOutcome::Evaluatable {
        root: ready_root, ..
    } = &ready.outcome
    else {
        unreachable!("the first preparation is ready");
    };
    assert_eq!(ready_root, &batch.roots[0].root);
    assert_eq!(missing.request_ordinal, 1);
    assert_eq!(missing.request, unknown);
    assert_eq!(missing.requested_function, key(unknown.function));
    assert!(matches!(
        &missing.outcome,
        super::TypedPanicRootPreparationOutcome::Missing {
            reason: crate::analysis::interpret::IncompleteReason::MissingBody {
                function,
                path,
                source_range: None,
                trace,
            },
        } if *function == unknown.function
            && path == &unknown.path
            && trace.steps.is_empty()
    ));
    assert_eq!(ready.expected_scope, missing.expected_scope);
    assert_eq!(later_ready.request_ordinal, 2);
    assert_eq!(later_ready.request, second);
    assert_eq!(later_ready.requested_function, key(second_function));
    assert_eq!(later_ready.expected_scope, ready.expected_scope);
    assert!(matches!(
        later_ready.outcome,
        super::TypedPanicRootPreparationOutcome::Evaluatable {
            report_index: 1,
            ..
        }
    ));
    let super::TypedPanicRootPreparationOutcome::Evaluatable {
        root: later_root, ..
    } = &later_ready.outcome
    else {
        unreachable!("the late preparation is ready");
    };
    assert_eq!(later_root, &batch.roots[1].root);

    assert_eq!(batch.roots.len(), 2);
    assert_eq!(batch.compiler_asserts.len(), 2);
    assert_eq!(batch.root_contracts.len(), 2);
    assert_eq!(batch.completeness.len(), 2);
    assert_eq!(batch.ambiguities.len(), 2);
    let expected_ready = [valid.function, second.function];
    assert_eq!(
        batch
            .compiler_asserts
            .iter()
            .map(|report| report.function)
            .collect::<Vec<_>>(),
        expected_ready
    );
    assert_eq!(
        batch
            .roots
            .iter()
            .map(|report| report.function)
            .collect::<Vec<_>>(),
        expected_ready
    );
    assert_eq!(
        batch
            .root_contracts
            .iter()
            .map(|report| report.function)
            .collect::<Vec<_>>(),
        expected_ready
    );
    assert_eq!(
        batch
            .completeness
            .iter()
            .map(|report| report.function)
            .collect::<Vec<_>>(),
        expected_ready
    );
    assert_eq!(
        batch
            .ambiguities
            .iter()
            .map(|report| report.function)
            .collect::<Vec<_>>(),
        expected_ready
    );
}

#[test]
fn all_missing_roots_keep_order_without_fabricating_ready_lanes() {
    let facts = root_preparation_artifact(&[function(121)]);
    let first = InterpretationRoot {
        function: function(122),
        path: String::from("fixture::first_missing"),
        kind: ReportRootKind::Concrete,
    };
    let second = InterpretationRoot {
        function: exact_function(123),
        path: String::from("fixture::second_missing"),
        kind: ReportRootKind::Generic,
    };
    let requests = [first.clone(), second.clone()];

    let batch = super::evaluate_typed_panic_call_roots(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        &[],
        Vec::new(),
        &[],
        &requests,
        &SniffTestConfig::default(),
    )
    .expect("the exact all-missing validation probe accepts missing local roots");

    assert!(batch.roots.is_empty());
    assert!(batch.compiler_asserts.is_empty());
    assert!(batch.root_contracts.is_empty());
    assert!(batch.completeness.is_empty());
    assert!(batch.ambiguities.is_empty());
    assert_eq!(batch.root_preparations.len(), 2);
    let local_scope =
        crate::analysis::facts::workspace::ArtifactScopeId::for_in_memory(LOCAL_CRATE, 0);
    for (ordinal, (preparation, request)) in
        batch.root_preparations.iter().zip(&requests).enumerate()
    {
        assert_eq!(preparation.request_ordinal, ordinal);
        assert_eq!(&preparation.request, request);
        assert_eq!(preparation.expected_scope, local_scope);
        assert_eq!(preparation.requested_function, key(request.function));
        assert!(matches!(
            &preparation.outcome,
            super::TypedPanicRootPreparationOutcome::Missing {
                reason: crate::analysis::interpret::IncompleteReason::MissingBody {
                    function,
                    path,
                    source_range: None,
                    trace,
                },
            } if function == &request.function
                && path == &request.path
                && trace.steps.is_empty()
        ));
    }
}

#[test]
fn all_missing_roots_still_run_the_core_validation_probe() {
    let mut facts = root_preparation_artifact(&[function(124)]);
    facts
        .tables
        .retain(|table| table.schema.as_str() != PanicContractFact::ID);
    let missing = InterpretationRoot {
        function: function(125),
        path: String::from("fixture::missing"),
        kind: ReportRootKind::Generic,
    };

    let error = super::evaluate_typed_panic_call_roots(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        &[],
        Vec::new(),
        &[],
        &[missing],
        &SniffTestConfig::default(),
    )
    .expect_err("all-missing roots must not bypass shared producer validation");

    let super::TypedPanicCallEvaluationError::Base(super::TypedPanicEvaluationError::Input(source)) =
        error
    else {
        panic!("the all-missing validation probe must return the core input error");
    };
    assert!(matches!(
        *source,
        crate::analysis::facts::panic::CompilerAssertInputError::PanicContracts(_)
    ));
}

#[test]
fn foreign_consumer_overlay_cannot_become_a_local_report_root() {
    const FOREIGN_CRATE: u64 = 2;
    let foreign_definition =
        serde_json::from_str::<StableDefPathHash>(&format!("\"{FOREIGN_CRATE:016x}{:016x}\"", 126))
            .expect("valid foreign stable definition hash");
    let foreign_instance = serde_json::from_str::<StableInstanceHash>(&format!("\"{:032x}\"", 126))
        .expect("valid foreign instance hash");
    let foreign = FunctionId::exact(foreign_definition, foreign_instance);
    let facts = foreign_consumer_overlay_artifact(foreign);
    let runtime = crate::analysis::cache::RustcArtifactId::new(FOREIGN_CRATE, "2".repeat(32));
    let request = InterpretationRoot {
        function: foreign,
        path: String::from("dependency::instantiated"),
        kind: ReportRootKind::Concrete,
    };

    let error = super::evaluate_typed_panic_call_roots(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        &[],
        Vec::new(),
        &[runtime],
        &[request],
        &SniffTestConfig::default(),
    )
    .expect_err("a foreign definition cannot become a local report root");

    assert!(matches!(
        error,
        super::TypedPanicCallEvaluationError::RootPreparation(source)
            if matches!(*source, crate::analysis::facts::program::workspace_index::WorkspaceProgramIndexError::InvalidQuery { ref reason }
                if reason.contains("not local stable crate"))
    ));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one parity fixture compares original-order output across both rendering and source modes"
)]
fn missing_root_batch_adapter_has_exact_legacy_order_and_source_parity() {
    let first_function = function(127);
    let second_function = function(128);
    let facts = root_preparation_artifact(&[first_function, second_function]);
    let legacy = legacy_root_preparation_artifact(&[first_function, second_function]);
    let first = InterpretationRoot {
        function: first_function,
        path: String::from("fixture::first"),
        kind: ReportRootKind::Concrete,
    };
    let missing = InterpretationRoot {
        function: function(129),
        path: String::from("fixture::missing"),
        kind: ReportRootKind::Generic,
    };
    let second = InterpretationRoot {
        function: second_function,
        path: String::from("fixture::second"),
        kind: ReportRootKind::Concrete,
    };
    let roots = [first, missing, second];
    let mut config = SniffTestConfig::default();
    config.analysis.node_limit = 0;
    let batch = super::evaluate_typed_panic_call_roots(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        &[],
        Vec::new(),
        &[],
        &roots,
        &config,
    )
    .expect("mixed root preparation evaluates");
    assert_eq!(
        batch
            .compiler_asserts
            .iter()
            .map(|report| report.function)
            .collect::<Vec<_>>(),
        [first_function, second_function]
    );
    let legacy_reports = interpret(&legacy, &roots, &config);
    let available = FixtureSources {
        root: roots[1].function,
        file: SourceFileIr {
            id: SourceFileId::new("fixture-file"),
            filename: String::from("src/lib.rs"),
            content_hash: String::from("sha256:typed-panic-root-preparation"),
            byte_len: 128,
        },
    };

    for show_full_stack_trace in [false, true] {
        let expected = legacy_reports
            .iter()
            .zip(&roots)
            .flat_map(|(report, root)| {
                report
                    .completeness
                    .panic
                    .reasons
                    .iter()
                    .cloned()
                    .map(|reason| {
                        adapt_typed_panic_incomplete_finding(
                            &available,
                            root,
                            reason,
                            show_full_stack_trace,
                        )
                    })
            })
            .collect::<Vec<_>>();
        let actual = super::adapt_typed_panic_call_completeness_batch(
            &available,
            &batch,
            &roots,
            show_full_stack_trace,
        )
        .expect("the complete sparse batch adapts");
        assert_eq!(actual, expected);
        let authority = adapt_typed_panic_authority_batch(
            &available,
            batch.clone(),
            &roots,
            show_full_stack_trace,
        )
        .expect("the unified authority preserves the complete sparse batch");
        assert_eq!(authority, expected);
        assert_eq!(actual.len(), 3);
        assert!(actual[0].reason.contains("node limit"));
        assert!(actual[1].reason.contains("could not load the body"));
        assert!(actual[2].reason.contains("node limit"));
        assert_eq!(actual[1].root_span.as_deref(), Some("bytes 5..10"));
        let diagnostic_span = actual[1]
            .diagnostic
            .span
            .expect("available missing root has a diagnostic span");
        assert_eq!((diagnostic_span.lo().0, diagnostic_span.hi().0), (5, 10));

        let expected_degraded = legacy_reports
            .iter()
            .zip(&roots)
            .flat_map(|(report, root)| {
                report
                    .completeness
                    .panic
                    .reasons
                    .iter()
                    .cloned()
                    .map(|reason| {
                        adapt_typed_panic_incomplete_finding(
                            &UnavailableSources,
                            root,
                            reason,
                            show_full_stack_trace,
                        )
                    })
            })
            .collect::<Vec<_>>();
        let actual_degraded = super::adapt_typed_panic_call_completeness_batch(
            &UnavailableSources,
            &batch,
            &roots,
            show_full_stack_trace,
        )
        .expect("the complete sparse batch degrades unavailable sources");
        assert_eq!(actual_degraded, expected_degraded);
        let authority_degraded = adapt_typed_panic_authority_batch(
            &UnavailableSources,
            batch.clone(),
            &roots,
            show_full_stack_trace,
        )
        .expect("the unified authority degrades the complete sparse batch");
        assert_eq!(authority_degraded, expected_degraded);
        assert!(actual_degraded[1].root_span.is_none());
        assert!(actual_degraded[1].diagnostic.span.is_none());
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one hostile matrix keeps every sparse lane and root binding visible"
)]
fn missing_root_batch_adapter_preflights_every_sparse_lane_before_sources() {
    let first_function = function(130);
    let second_function = function(131);
    let facts = root_preparation_artifact(&[first_function, second_function]);
    let roots = [
        InterpretationRoot {
            function: first_function,
            path: String::from("fixture::first"),
            kind: ReportRootKind::Concrete,
        },
        InterpretationRoot {
            function: function(132),
            path: String::from("fixture::missing"),
            kind: ReportRootKind::Generic,
        },
        InterpretationRoot {
            function: second_function,
            path: String::from("fixture::second"),
            kind: ReportRootKind::Concrete,
        },
    ];
    let mut config = SniffTestConfig::default();
    config.analysis.node_limit = 0;
    let batch = super::evaluate_typed_panic_call_roots(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        &[],
        Vec::new(),
        &[],
        &roots,
        &config,
    )
    .expect("hostile adapter fixture evaluates");

    let mut missing_preparation = batch.clone();
    missing_preparation.root_preparations.pop();
    let mut nondense_ready = batch.clone();
    let super::TypedPanicRootPreparationOutcome::Evaluatable { report_index, .. } =
        &mut nondense_ready.root_preparations[2].outcome
    else {
        panic!("the late preparation is ready");
    };
    *report_index = 2;
    let mut fabricated_missing_source = batch.clone();
    let super::TypedPanicRootPreparationOutcome::Missing { reason } =
        &mut fabricated_missing_source.root_preparations[1].outcome
    else {
        panic!("the middle preparation is missing");
    };
    let crate::analysis::interpret::IncompleteReason::MissingBody { source_range, .. } = reason
    else {
        panic!("the missing preparation uses missing-body evidence");
    };
    *source_range = Some(range(1, 2));
    let mut wrong_scope = batch.clone();
    wrong_scope.root_preparations[1].expected_scope =
        crate::analysis::facts::workspace::ArtifactScopeId::for_in_memory(LOCAL_CRATE, 99);
    let mut late_compiler_assert = batch.clone();
    late_compiler_assert.compiler_asserts[1].path =
        String::from("fixture::hostile_compiler_assert");
    let mut compiler_cross_lane_root = batch.clone();
    compiler_cross_lane_root.compiler_asserts[1].root.domain =
        DomainId::new("hostile.panic").unwrap();
    let mut late_call = batch.clone();
    late_call.roots[1].path = String::from("fixture::hostile_call");
    let mut late_root_contract = batch.clone();
    late_root_contract.root_contracts[1].root.domain = DomainId::new("hostile.panic").unwrap();
    let mut late_ambiguity = batch.clone();
    late_ambiguity.ambiguities[1].kind = ReportRootKind::Generic;
    let mut cross_lane_root = batch.clone();
    cross_lane_root.completeness[1].root.domain = DomainId::new("hostile.panic").unwrap();
    let mut coordinated_root_swap = batch.clone();
    let replacement = coordinated_root_swap.roots[1].root.clone();
    let super::TypedPanicRootPreparationOutcome::Evaluatable {
        root: prepared_root,
        ..
    } = &mut coordinated_root_swap.root_preparations[0].outcome
    else {
        panic!("the first preparation is ready");
    };
    *prepared_root = replacement.clone();
    coordinated_root_swap.compiler_asserts[0].root = replacement.clone();
    coordinated_root_swap.roots[0].root = replacement.clone();
    coordinated_root_swap.root_contracts[0].root = replacement.clone();
    coordinated_root_swap.completeness[0].root = replacement.clone();
    for issue in &mut coordinated_root_swap.completeness[0].issues {
        issue.root = replacement.clone();
    }
    coordinated_root_swap.ambiguities[0].root = replacement;

    for (name, hostile) in [
        ("missing preparation", missing_preparation),
        ("nondense ready index", nondense_ready),
        ("fabricated missing source", fabricated_missing_source),
        ("different expected scope", wrong_scope),
        ("late compiler-assert metadata", late_compiler_assert),
        ("compiler-assert cross-lane root", compiler_cross_lane_root),
        ("late call metadata", late_call),
        ("late root-contract root", late_root_contract),
        ("late ambiguity metadata", late_ambiguity),
        ("cross-lane root", cross_lane_root),
        ("coordinated ready-root swap", coordinated_root_swap),
    ] {
        let sources = CountingSources::default();
        assert!(
            super::adapt_typed_panic_call_completeness_batch(&sources, &hostile, &roots, true,)
                .is_err(),
            "{name} must reject the complete sparse batch"
        );
        assert_eq!(sources.calls.get(), 0, "{name} consulted sources");
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one registry contract pins every production dependency and authority guard"
)]
fn production_authority_registry_installs_every_panic_pack_in_dependency_order() {
    let registry =
        super::typed_panic_authority_registry().expect("production authority registry installs");
    assert!(
        registry
            .schemas()
            .descriptor_for::<crate::analysis::facts::panic::PanicCompletenessOutcome>()
            .is_ok()
    );
    assert!(
        registry
            .schemas()
            .descriptor_for::<crate::analysis::facts::panic::PanicAnalysisIncompleteIssue>()
            .is_ok()
    );
    assert!(
        registry
            .schemas()
            .descriptor_for::<crate::analysis::facts::evidence::EvidenceUseRecord>()
            .is_ok()
    );
    assert!(
        registry
            .schemas()
            .descriptor_for::<crate::analysis::facts::evidence::AmbiguousEvidenceReuseIssue>()
            .is_ok()
    );
    let root_issue_schema = registry
        .schemas()
        .descriptor_for::<crate::analysis::facts::panic::DuplicatePanicRootRequirementIssue>()
        .expect("the authority registry installs the strict root-contract issue");
    assert_eq!(root_issue_schema.version(), 1);
    assert_eq!(root_issue_schema.kind(), TableKind::Issue);
    for rule in [
        "sniff-test.panic.emit-call-inputs",
        "sniff-test.panic.emit-compiler-assert-inputs",
        "sniff-test.panic.match-call-evidence",
        "sniff-test.panic.match-assert-evidence",
        "sniff-test.evidence.detect-reuse",
        "sniff-test.panic.emit-completeness",
        "sniff-test.panic.report-incomplete",
        "sniff-test.panic.report-duplicate-root-requirements",
    ] {
        assert!(
            registry
                .evaluation_rules()
                .descriptor(&PassId::new(rule).unwrap())
                .is_some(),
            "missing production authority rule {rule}"
        );
    }
    let root_reporter = registry
        .evaluation_rules()
        .descriptor(&PassId::new("sniff-test.panic.report-duplicate-root-requirements").unwrap())
        .expect("the authority registry installs the root-contract reporter");
    assert_eq!(
        root_reporter
            .reads()
            .map(SchemaId::as_str)
            .collect::<Vec<_>>(),
        [
            FunctionEntity::ID,
            CallableEntity::ID,
            SourceAnchorEntity::ID,
            PanicContractFact::ID,
            PanicRequirement::ID,
        ]
    );
    assert_eq!(
        root_reporter
            .writes()
            .map(SchemaId::as_str)
            .collect::<Vec<_>>(),
        [crate::analysis::facts::panic::DuplicatePanicRootRequirementIssue::ID]
    );
    let schedule = registry
        .evaluation_rules()
        .schedule()
        .expect("the combined production schedule is acyclic");
    let position = |rule: &str| {
        assert_eq!(
            schedule
                .iter()
                .filter(|candidate| candidate.as_str() == rule)
                .count(),
            1,
            "{rule} must be scheduled exactly once"
        );
        schedule
            .iter()
            .position(|candidate| candidate.as_str() == rule)
            .expect("the rule is present")
    };
    assert!(
        position("sniff-test.panic.emit-call-inputs")
            < position("sniff-test.panic.match-call-evidence")
    );
    assert!(
        position("sniff-test.panic.emit-compiler-assert-inputs")
            < position("sniff-test.panic.match-assert-evidence")
    );
    assert!(
        position("sniff-test.panic.match-call-evidence")
            < position("sniff-test.evidence.detect-reuse")
    );
    assert!(
        position("sniff-test.panic.match-assert-evidence")
            < position("sniff-test.evidence.detect-reuse")
    );
    let _ = position("sniff-test.panic.report-duplicate-root-requirements");
}

#[test]
fn compiler_assert_oracle_registry_remains_narrower_than_production_authority() {
    let registry =
        compiler_assert_oracle_registry_for_test().expect("compiler-assert oracle installs");
    assert!(
        registry
            .schemas()
            .descriptor_for::<crate::analysis::facts::evidence::AmbiguousEvidenceReuseIssue>()
            .is_err()
    );
    assert!(
        registry
            .evaluation_rules()
            .descriptor(&PassId::new("sniff-test.evidence.detect-reuse").unwrap())
            .is_none()
    );
    assert!(
        registry
            .schemas()
            .descriptor_for::<crate::analysis::facts::panic::DuplicatePanicRootRequirementIssue>()
            .is_err()
    );
    assert!(
        registry
            .evaluation_rules()
            .descriptor(
                &PassId::new("sniff-test.panic.report-duplicate-root-requirements").unwrap()
            )
            .is_none()
    );
}

#[test]
fn combined_evaluator_projects_compiler_asserts_from_its_single_root_evaluation() {
    let root_function = function(184);
    let facts = root_contract_artifact(
        root_function,
        root_function,
        FunctionBodyProvenance::DefiningArtifact,
        None,
    );
    let requested_root = root(root_function);

    super::reset_compiler_assert_projector_prepares();
    let batch = super::evaluate_typed_panic_call_roots(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        &[],
        Vec::new(),
        &[],
        std::slice::from_ref(&requested_root),
        &SniffTestConfig::default(),
    )
    .expect("the combined evaluator owns the compiler-assert lane");

    let [report] = batch.compiler_asserts.as_slice() else {
        panic!("one ready root must produce one compiler-assert report");
    };
    assert_eq!(report.function, requested_root.function);
    assert_eq!(report.path, requested_root.path);
    assert_eq!(report.kind, requested_root.kind);
    assert_eq!(report.issues.len(), 1);
    assert!(batch.roots[0].issues.is_empty());
    assert_eq!(super::compiler_assert_projector_prepares(), 1);
}

#[test]
fn unified_authority_adapter_has_exact_compiler_assert_parity_in_every_source_mode() {
    let root_function = function(185);
    let facts = root_contract_artifact(
        root_function,
        root_function,
        FunctionBodyProvenance::DefiningArtifact,
        None,
    );
    let requested_root = root(root_function);
    let batch = super::evaluate_typed_panic_call_roots(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        &[],
        Vec::new(),
        &[],
        std::slice::from_ref(&requested_root),
        &SniffTestConfig::default(),
    )
    .expect("the unified authority fixture evaluates");
    let sources = FixtureSources {
        root: root_function,
        file: SourceFileIr {
            id: SourceFileId::new("fixture-file"),
            filename: String::from("src/lib.rs"),
            content_hash: String::from("sha256:typed-panic-call-fixture"),
            byte_len: 128,
        },
    };

    for show_full_stack_trace in [false, true] {
        let expected = adapt_typed_panic_reports(
            &sources,
            batch.compiler_asserts.clone(),
            std::slice::from_ref(&requested_root),
            show_full_stack_trace,
        )
        .expect("the compiler-assert oracle adapts");
        let actual = adapt_typed_panic_authority_batch(
            &sources,
            batch.clone(),
            std::slice::from_ref(&requested_root),
            show_full_stack_trace,
        )
        .expect("the unified authority batch adapts");
        assert_eq!(actual, expected);

        let expected_degraded = adapt_typed_panic_reports(
            &UnavailableSources,
            batch.compiler_asserts.clone(),
            std::slice::from_ref(&requested_root),
            show_full_stack_trace,
        )
        .expect("the compiler-assert oracle degrades unavailable sources");
        let actual_degraded = adapt_typed_panic_authority_batch(
            &UnavailableSources,
            batch.clone(),
            std::slice::from_ref(&requested_root),
            show_full_stack_trace,
        )
        .expect("the unified authority batch degrades unavailable sources");
        assert_eq!(actual_degraded, expected_degraded);
    }
}

#[test]
fn unified_authority_adapter_projects_each_call_dto_once() {
    let root_function = function(189);
    let facts = sink_artifact(root_function, exact_function(190));
    let requested_root = root(root_function);
    let mut config = SniffTestConfig::default();
    config.panics.panic_sink_namespaces =
        PathPatterns::new(vec![String::from("fixture::sink")]).unwrap();
    super::reset_obligation_index_passes();
    let batch = super::evaluate_typed_panic_call_roots(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        &[],
        Vec::new(),
        &[],
        std::slice::from_ref(&requested_root),
        &config,
    )
    .expect("the call-projection work fixture evaluates");
    assert_eq!(batch.roots[0].issues.len(), 1);
    assert_eq!(super::obligation_index_passes(), 1);

    super::reset_interpreted_finding_projections();
    let findings = adapt_typed_panic_authority_batch(
        &NoSources,
        batch,
        std::slice::from_ref(&requested_root),
        false,
    )
    .expect("the unified authority batch adapts");

    assert_eq!(findings.len(), 1);
    assert_eq!(super::interpreted_finding_projections(), 1);
}

#[test]
fn unified_authority_adapter_rejects_a_late_renderer_dto_before_source_access() {
    let root_function = function(186);
    let facts = root_contract_artifact(
        root_function,
        root_function,
        FunctionBodyProvenance::DefiningArtifact,
        None,
    );
    let requested_root = root(root_function);
    let mut batch = super::evaluate_typed_panic_call_roots(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        &[],
        Vec::new(),
        &[],
        std::slice::from_ref(&requested_root),
        &SniffTestConfig::default(),
    )
    .expect("the hostile unified-adapter fixture evaluates");
    let issue = batch.compiler_asserts[0].issues[0].clone();
    batch.compiler_asserts[0].issues.push(issue);
    let late = batch.compiler_asserts[0]
        .issues
        .last_mut()
        .expect("the late compiler issue is retained");
    late.diagnostic
        .labels
        .push(crate::analysis::facts::render::RenderedLabel {
            anchor: late.issue.reference.clone(),
            message: String::from("hostile late label"),
        });

    let sources = CountingSources::default();
    let error = adapt_typed_panic_authority_batch(
        &sources,
        batch,
        std::slice::from_ref(&requested_root),
        true,
    )
    .expect_err("a late unsupported renderer DTO rejects the whole authority batch");
    assert!(error.to_string().contains("unsupported `labels`"));
    assert_eq!(sources.calls.get(), 0);
}

#[test]
fn unified_authority_adapter_preprojects_late_call_dtos_before_source_access() {
    let root_function = function(187);
    let facts = sink_artifact(root_function, exact_function(188));
    let requested_root = root(root_function);
    let mut config = SniffTestConfig::default();
    config.panics.panic_sink_namespaces =
        PathPatterns::new(vec![String::from("fixture::sink")]).unwrap();
    let mut batch = super::evaluate_typed_panic_call_roots(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        &[],
        Vec::new(),
        &[],
        std::slice::from_ref(&requested_root),
        &config,
    )
    .expect("the hostile call-DTO fixture evaluates");
    let issue = batch.roots[0].issues[0].clone();
    batch.roots[0].issues.push(issue);
    batch.roots[0]
        .issues
        .last_mut()
        .expect("the late call issue is retained")
        .kind = super::TypedPanicCallIssueKind::Unsatisfied {
        boundary: super::PanicCallBoundaryKind::Opaque {
            opaque_kind: super::PanicCallOpaqueKind::ExplicitOpaque,
            description: String::from("hostile mismatched opaque DTO"),
        },
    };

    let sources = CountingSources::default();
    let error = adapt_typed_panic_authority_batch(
        &sources,
        batch,
        std::slice::from_ref(&requested_root),
        true,
    )
    .expect_err("a late unprojectable call DTO rejects the whole authority batch");
    assert!(error.to_string().contains("opaque boundary description"));
    assert_eq!(sources.calls.get(), 0);
}

#[test]
fn call_lane_ambiguity_has_exact_compact_full_and_degraded_legacy_parity() {
    let root_function = function(121);
    let first_documented = exact_function(122);
    let second_documented = exact_function(123);
    let facts = ambiguous_call_marker_artifact(root_function, first_documented, second_documented);
    let legacy =
        legacy_ambiguous_call_marker_artifact(root_function, first_documented, second_documented);
    let requested_root = root(root_function);
    let batch = super::evaluate_typed_panic_call_roots(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        &[],
        Vec::new(),
        &[],
        std::slice::from_ref(&requested_root),
        &SniffTestConfig::default(),
    )
    .expect("the combined evaluator projects the call-lane ambiguity");
    let [ambiguity] = batch.ambiguities.as_slice() else {
        panic!("one root ambiguity report must be retained");
    };
    let [issue] = ambiguity.issues.as_slice() else {
        panic!("one physical marker reused by two groups must be ambiguous");
    };
    assert_eq!(issue.function, root_function);
    assert_eq!(issue.function_path, "fixture::root");
    assert_eq!(issue.source_range, Some(range(90, 95)));
    assert_eq!(issue.effect_count, 2);
    assert_eq!(issue.trace.steps.len(), 1);
    assert_eq!(issue.trace.steps[0].call, CallId::new(3));

    let legacy = interpret(
        &legacy,
        std::slice::from_ref(&requested_root),
        &SniffTestConfig::default(),
    );
    let legacy_finding = legacy[0]
        .findings
        .iter()
        .find(|finding| {
            matches!(
                finding.kind,
                InterpretedFindingKind::AmbiguousPanicMarker { effect_count: 2 }
            )
        })
        .expect("legacy interpretation emits the same marker ambiguity");
    let sources = FixtureSources {
        root: root_function,
        file: SourceFileIr {
            id: SourceFileId::new("fixture-file"),
            filename: String::from("src/lib.rs"),
            content_hash: String::from("sha256:typed-panic-call-fixture"),
            byte_len: 256,
        },
    };
    for show_full_stack_trace in [false, true] {
        let expected = adapt_typed_panic_call_finding(
            &sources,
            &requested_root,
            legacy_finding,
            show_full_stack_trace,
        );
        let actual = adapt_typed_panic_ambiguity_reports(
            &sources,
            batch.ambiguities.clone(),
            std::slice::from_ref(&requested_root),
            show_full_stack_trace,
        )
        .expect("the owned ambiguity report adapts atomically");
        assert_eq!(actual, [expected]);

        let expected_degraded = adapt_typed_panic_call_finding(
            &UnavailableSources,
            &requested_root,
            legacy_finding,
            show_full_stack_trace,
        );
        let actual_degraded = adapt_typed_panic_ambiguity_reports(
            &UnavailableSources,
            batch.ambiguities.clone(),
            std::slice::from_ref(&requested_root),
            show_full_stack_trace,
        )
        .expect("unavailable marker source degrades through the legacy boundary");
        assert_eq!(actual_degraded, [expected_degraded]);
    }
}

#[test]
fn one_physical_marker_coordinates_distinct_claims_across_call_groups() {
    let root_function = function(124);
    let first_documented = exact_function(125);
    let second_documented = exact_function(126);
    let facts = ambiguous_multi_claim_call_marker_artifact(
        root_function,
        first_documented,
        second_documented,
    );
    let requested_root = root(root_function);
    let (call, _, fixture) = evaluate_typed_panic_call_with_projection_fixture(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        [],
        &[],
        &requested_root,
        &SniffTestConfig::default(),
    )
    .expect("distinct claims on one physical marker coordinate across call groups");

    assert_eq!(fixture.evidence_uses.len(), 2);
    assert_eq!(fixture.ambiguities.len(), 1);
    assert_eq!(
        fixture
            .inputs
            .calls()
            .map(|call| call.expect("prepared call remains valid").markers().len())
            .sum::<usize>(),
        3,
        "the nonmatching named claim remains active but emits no evidence use"
    );
    assert_eq!(
        fixture
            .evidence_uses
            .iter()
            .map(|usage| usage.data.claim())
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        2
    );
    let nonmatching = fixture
        .obligations
        .iter()
        .flat_map(|row| row.data.active_markers())
        .find(|marker| marker.data().key().source_ordinal() == 2)
        .expect("the source-ordinal-two named claim remains active");
    assert_eq!(
        nonmatching.data().selector(),
        &EvidenceClaimSelector::Named(String::from("does-not-exist"))
    );
    assert!(
        fixture
            .evidence_uses
            .iter()
            .all(|usage| usage.data.claim() != nonmatching.claim()),
        "the active named claim matches no obligation requirement"
    );
    assert_eq!(fixture.ambiguities[0].data.groups().len(), 2);
    assert_eq!(call.root, fixture.ambiguities[0].context.root);

    let error = evaluate_typed_panic_call_with_ambiguity_corruption(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        &requested_root,
        &SniffTestConfig::default(),
        AmbiguityProjectionCorruption::EvidenceNonmatchingClaim,
    )
    .expect_err("an injected use for the exact nonmatching active claim must fail");
    assert!(error.to_string().contains("not bijective"));
}

#[test]
fn propagated_function_marker_reused_by_assertions_has_exact_legacy_parity() {
    let root_function = function(127);
    let helper_function = exact_function(128);
    let facts = ambiguous_assert_marker_artifact(root_function, helper_function, false);
    let legacy = legacy_ambiguous_assert_marker_artifact(root_function, helper_function);
    let requested_root = root(root_function);
    let (_, _, projection) = evaluate_typed_panic_call_with_projection_fixture(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        [],
        &[],
        &requested_root,
        &SniffTestConfig::default(),
    )
    .expect("the propagated assertion fixture exposes raw rows");
    assert_eq!(
        projection.evidence_uses.len(),
        2,
        "both descendant assertions must consume the propagated marker"
    );
    assert_eq!(projection.ambiguities.len(), 1);
    let batch = super::evaluate_typed_panic_call_roots(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        &[],
        Vec::new(),
        &[],
        std::slice::from_ref(&requested_root),
        &SniffTestConfig::default(),
    )
    .expect("the combined evaluator projects propagated compiler-assert ambiguity");
    let [ambiguity] = batch.ambiguities.as_slice() else {
        panic!("one root ambiguity report must be retained");
    };
    let [issue] = ambiguity.issues.as_slice() else {
        panic!("one propagated marker reused by two assertions must be ambiguous");
    };
    assert_eq!(issue.function, root_function);
    assert_eq!(issue.function_path, "fixture::root");
    assert_eq!(issue.source_range, Some(range(90, 95)));
    assert_eq!(issue.effect_count, 2);
    assert_eq!(issue.trace.steps.len(), 2);
    assert_eq!(issue.trace.steps[0].call, CallId::new(3));
    assert_eq!(issue.trace.steps[1].call, CallId::new(1));
    assert_eq!(
        issue.trace.steps[1].kind,
        crate::analysis::interpret::InterpretedTraceStepKind::Reachability(CallEdgeKindIr::Assert)
    );

    let legacy = interpret(
        &legacy,
        std::slice::from_ref(&requested_root),
        &SniffTestConfig::default(),
    );
    let legacy_finding = legacy[0]
        .findings
        .iter()
        .find(|finding| {
            matches!(
                finding.kind,
                InterpretedFindingKind::AmbiguousPanicMarker { effect_count: 2 }
            )
        })
        .expect("legacy interpretation emits the propagated marker ambiguity");
    let sources = FixtureSources {
        root: root_function,
        file: SourceFileIr {
            id: SourceFileId::new("fixture-file"),
            filename: String::from("src/lib.rs"),
            content_hash: String::from("sha256:typed-panic-call-fixture"),
            byte_len: 256,
        },
    };
    for show_full_stack_trace in [false, true] {
        let expected = adapt_typed_panic_call_finding(
            &sources,
            &requested_root,
            legacy_finding,
            show_full_stack_trace,
        );
        let actual = adapt_typed_panic_ambiguity_reports(
            &sources,
            batch.ambiguities.clone(),
            std::slice::from_ref(&requested_root),
            show_full_stack_trace,
        )
        .expect("the owned compiler-assert ambiguity report adapts atomically");
        assert_eq!(actual, [expected]);

        let expected_degraded = adapt_typed_panic_call_finding(
            &UnavailableSources,
            &requested_root,
            legacy_finding,
            show_full_stack_trace,
        );
        let actual_degraded = adapt_typed_panic_ambiguity_reports(
            &UnavailableSources,
            batch.ambiguities.clone(),
            std::slice::from_ref(&requested_root),
            show_full_stack_trace,
        )
        .expect("unavailable assertion marker source degrades through the legacy boundary");
        assert_eq!(actual_degraded, [expected_degraded]);
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one parity test freezes same-order lane dispatch across compact, full, and degraded DTOs"
)]
fn mixed_call_and_assert_witness_zero_dispatches_by_source_schema_with_legacy_parity() {
    let root_function = function(129);
    let documented_function = exact_function(130);
    let facts = ambiguous_mixed_lane_marker_artifact(root_function, documented_function);
    let legacy = legacy_ambiguous_mixed_lane_marker_artifact(root_function, documented_function);
    let requested_root = root(root_function);
    let (_, _, projection) = evaluate_typed_panic_call_with_projection_fixture(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        [],
        &[],
        &requested_root,
        &SniffTestConfig::default(),
    )
    .expect("the mixed-lane fixture exposes its exact producer rows");
    assert_eq!(projection.evidence_uses.len(), 2);
    assert_eq!(projection.ambiguities.len(), 1);
    assert!(
        projection
            .evidence_uses
            .iter()
            .all(|usage| usage.data.witness_order() == 0),
        "call and compiler-assert lanes intentionally collide at witness zero"
    );
    assert_eq!(
        projection
            .evidence_uses
            .iter()
            .map(|usage| usage.producer.as_str())
            .collect::<std::collections::BTreeSet<_>>(),
        [
            "sniff-test.panic.match-assert-evidence",
            "sniff-test.panic.match-call-evidence",
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(
        projection.ambiguities[0]
            .data
            .witness_source()
            .row()
            .schema
            .as_str(),
        crate::analysis::facts::panic::model::MirAssertFact::ID,
        "the shorter assert trace is the canonical witness"
    );

    let batch = super::evaluate_typed_panic_call_roots(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        &[],
        Vec::new(),
        &[],
        std::slice::from_ref(&requested_root),
        &SniffTestConfig::default(),
    )
    .expect("the same-order mixed lanes project without ordinal aliasing");
    let [issue] = batch.ambiguities[0].issues.as_slice() else {
        panic!("one mixed call/assert ambiguity must be projected");
    };
    assert_eq!(issue.function, root_function);
    assert_eq!(issue.source_range, Some(range(90, 95)));
    assert_eq!(issue.effect_count, 2);
    assert_eq!(issue.trace.steps.len(), 1);
    assert_eq!(issue.trace.steps[0].call, CallId::new(0));
    assert_eq!(
        issue.trace.steps[0].kind,
        crate::analysis::interpret::InterpretedTraceStepKind::Reachability(CallEdgeKindIr::Assert)
    );

    let legacy = interpret(
        &legacy,
        std::slice::from_ref(&requested_root),
        &SniffTestConfig::default(),
    );
    let legacy_finding = legacy[0]
        .findings
        .iter()
        .find(|finding| {
            matches!(
                finding.kind,
                InterpretedFindingKind::AmbiguousPanicMarker { effect_count: 2 }
            )
        })
        .expect("legacy interpretation emits the same mixed-lane ambiguity");
    let sources = FixtureSources {
        root: root_function,
        file: SourceFileIr {
            id: SourceFileId::new("fixture-file"),
            filename: String::from("src/lib.rs"),
            content_hash: String::from("sha256:typed-panic-call-fixture"),
            byte_len: 256,
        },
    };
    for show_full_stack_trace in [false, true] {
        let expected = adapt_typed_panic_call_finding(
            &sources,
            &requested_root,
            legacy_finding,
            show_full_stack_trace,
        );
        let actual = adapt_typed_panic_ambiguity_reports(
            &sources,
            batch.ambiguities.clone(),
            std::slice::from_ref(&requested_root),
            show_full_stack_trace,
        )
        .expect("the mixed-lane normal DTO adapts atomically");
        assert_eq!(actual, [expected]);

        let expected_degraded = adapt_typed_panic_call_finding(
            &UnavailableSources,
            &requested_root,
            legacy_finding,
            show_full_stack_trace,
        );
        let actual_degraded = adapt_typed_panic_ambiguity_reports(
            &UnavailableSources,
            batch.ambiguities.clone(),
            std::slice::from_ref(&requested_root),
            show_full_stack_trace,
        )
        .expect("unavailable mixed-lane marker source degrades through the legacy boundary");
        assert_eq!(actual_degraded, [expected_degraded]);
    }
}

#[test]
fn ambiguity_adapter_preflights_the_entire_batch_before_source_resolution() {
    let root_function = function(139);
    let facts = ambiguous_multi_claim_call_marker_artifact(
        root_function,
        exact_function(140),
        exact_function(141),
    );
    let first_request = root(root_function);
    let batch = super::evaluate_typed_panic_call_roots(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        &[],
        Vec::new(),
        &[],
        std::slice::from_ref(&first_request),
        &SniffTestConfig::default(),
    )
    .expect("ambiguity adapter fixture evaluates");
    let first = batch
        .ambiguities
        .into_iter()
        .next()
        .expect("the fixture retains its root report");
    assert_eq!(first.issues.len(), 1);
    let second_request = InterpretationRoot {
        function: function(142),
        path: String::from("fixture::second_root"),
        kind: ReportRootKind::Concrete,
    };
    let mut second = first.clone();
    second.function = second_request.function;
    second.path.clone_from(&second_request.path);
    second.kind = second_request.kind;
    let roots = [first_request, second_request];

    let wrong_count_sources = CountingSources::default();
    let wrong_count = adapt_typed_panic_ambiguity_reports(
        &wrong_count_sources,
        vec![first.clone()],
        &roots,
        false,
    )
    .expect_err("a missing root report must reject the whole ambiguity batch");
    assert!(wrong_count.to_string().contains("ambiguity report batch"));
    assert_eq!(wrong_count_sources.calls.get(), 0);

    let reordered_sources = CountingSources::default();
    let reordered = adapt_typed_panic_ambiguity_reports(
        &reordered_sources,
        vec![second.clone(), first.clone()],
        &roots,
        false,
    )
    .expect_err("reordered root reports must reject the whole ambiguity batch");
    assert!(reordered.to_string().contains("ambiguity root report"));
    assert_eq!(reordered_sources.calls.get(), 0);

    second
        .issues
        .last_mut()
        .expect("the late report retains one normal issue")
        .root
        .domain = DomainId::new("hostile.panic").unwrap();
    let late_sources = CountingSources::default();
    let late =
        adapt_typed_panic_ambiguity_reports(&late_sources, vec![first, second], &roots, true)
            .expect_err("a late cross-root issue must reject the whole ambiguity batch");
    assert!(late.to_string().contains("ambiguity issue report"));
    assert_eq!(late_sources.calls.get(), 0);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the table freezes every independent raw ambiguity join boundary"
)]
fn ambiguity_projection_rejects_hostile_use_issue_context_and_activation_rows() {
    let root_function = function(132);
    let documented_function = exact_function(133);
    let facts = ambiguous_mixed_lane_marker_artifact(root_function, documented_function);
    let requested_root = root(root_function);
    for (name, corruption, expected) in [
        (
            "missing evidence use",
            AmbiguityProjectionCorruption::EvidenceMissing,
            "not bijective",
        ),
        (
            "duplicate evidence use",
            AmbiguityProjectionCorruption::EvidenceDuplicate,
            "repeat an exact producer payload",
        ),
        (
            "orphan evidence use",
            AmbiguityProjectionCorruption::EvidenceOrphan,
            "not bijective",
        ),
        (
            "altered evidence producer",
            AmbiguityProjectionCorruption::EvidenceProducer,
            "not bijective",
        ),
        (
            "missing ambiguity issue",
            AmbiguityProjectionCorruption::IssueMissing,
            "has no coordinator issue",
        ),
        (
            "duplicate ambiguity issue",
            AmbiguityProjectionCorruption::IssueDuplicate,
            "multiple issues report",
        ),
        (
            "orphan ambiguity issue",
            AmbiguityProjectionCorruption::IssueOrphan,
            "orphan physical-marker issue",
        ),
        (
            "altered issue producer",
            AmbiguityProjectionCorruption::IssueProducer,
            "not canonical",
        ),
        (
            "altered issue root",
            AmbiguityProjectionCorruption::IssueRoot,
            "not canonical",
        ),
        (
            "altered issue domain",
            AmbiguityProjectionCorruption::IssueDomain,
            "not canonical",
        ),
        (
            "missing marker source context",
            AmbiguityProjectionCorruption::IssueSourceContext,
            "not canonical",
        ),
        (
            "missing witness endpoint context",
            AmbiguityProjectionCorruption::IssueEndpointContext,
            "was altered",
        ),
        (
            "missing witness trace context",
            AmbiguityProjectionCorruption::IssueTraceContext,
            "was altered",
        ),
        (
            "altered witness source",
            AmbiguityProjectionCorruption::IssueWitnessSource,
            "was altered",
        ),
        (
            "altered witness endpoint",
            AmbiguityProjectionCorruption::IssueWitnessEndpoint,
            "was altered",
        ),
        (
            "altered witness order",
            AmbiguityProjectionCorruption::IssueWitnessOrder,
            "was altered",
        ),
        (
            "altered group union",
            AmbiguityProjectionCorruption::IssueGroups,
            "was altered",
        ),
        (
            "activation starts at another root",
            AmbiguityProjectionCorruption::ActivationRoot,
            "starts at another root",
        ),
        (
            "activation ends with unsupported relation",
            AmbiguityProjectionCorruption::ActivationUnsupportedFinalRelation,
            "unsupported final candidate relation",
        ),
    ] {
        let error = evaluate_typed_panic_call_with_ambiguity_corruption(
            TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
            &requested_root,
            &SniffTestConfig::default(),
            corruption,
        )
        .expect_err(name);
        assert!(
            error.to_string().contains(expected),
            "{name}: expected `{expected}`, got `{error}`"
        );
    }
}

#[test]
fn ambiguity_witness_rejects_an_unsupported_source_schema_before_ordinal_lookup() {
    let root_function = function(134);
    let facts = ambiguous_multi_claim_call_marker_artifact(
        root_function,
        exact_function(135),
        exact_function(136),
    );
    let requested_root = root(root_function);
    let (_, _, projection) = evaluate_typed_panic_call_with_projection_fixture(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        [],
        &[],
        &requested_root,
        &SniffTestConfig::default(),
    )
    .expect("the valid ambiguity fixture exposes one use to corrupt");
    let usage = &projection.evidence_uses[0].data;
    let hostile = crate::analysis::facts::evidence::EvidenceUseRecord::new(
        usage.domain().clone(),
        usage.claim().clone(),
        usage.endpoint().clone(),
        usage.group().clone(),
        usage.claim().as_row(),
        usage.trace().clone(),
        usage.witness_order(),
        usage.semantic_order().clone(),
    );
    let witnesses = super::AmbiguityWitnessIndex::new();
    let error = super::ambiguity_witness(&hostile, &witnesses)
        .err()
        .expect("an unsupported source schema must fail before witness lookup");
    assert!(
        error
            .to_string()
            .contains("unsupported witness source schema")
    );
}

#[test]
fn ambiguity_projection_rejects_contributing_activations_with_different_owners() {
    let root_function = function(137);
    let helper_function = exact_function(138);
    let facts = ambiguous_assert_marker_artifact(root_function, helper_function, true);
    let error = super::evaluate_typed_panic_call_roots(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        &[],
        Vec::new(),
        &[],
        &[root(root_function)],
        &SniffTestConfig::default(),
    )
    .expect_err("the same physical marker cannot acquire two semantic owners");
    assert!(error.to_string().contains("different owners"));
}

fn definition(local: u64) -> StableDefPathHash {
    serde_json::from_str(&format!("\"{LOCAL_CRATE:016x}{local:016x}\""))
        .expect("valid stable definition hash")
}

pub(in crate::cli::driver) fn function(local: u64) -> FunctionId {
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

pub(in crate::cli::driver) fn root(function: FunctionId) -> InterpretationRoot {
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

#[allow(
    clippy::too_many_arguments,
    reason = "the hostile helper makes every raw projection boundary explicit"
)]
fn project_hostile_missing_reason(
    inputs: &crate::analysis::facts::panic::PanicRootInputs,
    presentation_range: Option<SourceRangeIr>,
    request: &InterpretationRoot,
    root: &crate::analysis::facts::evaluation::EvaluationRoot,
    summary: &crate::analysis::facts::evaluation::TypedDerivedRow<
        crate::analysis::facts::panic::PanicCompletenessOutcome,
    >,
    issues: &[crate::analysis::facts::evaluation::TypedEvaluatedIssue<
        crate::analysis::facts::panic::PanicAnalysisIncompleteIssue,
    >],
    order: u64,
    hostile: &crate::analysis::facts::panic::PanicCompletenessReason,
) -> Result<super::TypedPanicCompletenessRootReport, super::TypedPanicCallEvaluationError> {
    let mut summary = summary.clone();
    let mut reasons = summary.data.reasons().to_vec();
    *reasons
        .iter_mut()
        .find(|reason| reason.traversal_order() == order)
        .expect("the hostile reason replaces an existing summary reason") = hostile.to_owned();
    summary.data = crate::analysis::facts::panic::PanicCompletenessOutcome::new(
        summary.data.expanded_bodies(),
        reasons,
    );
    let mut issues = issues.to_vec();
    let issue = issues
        .iter_mut()
        .find(|issue| issue.data.traversal_order() == order)
        .expect("the hostile reason replaces an existing issue");
    issue.data = crate::analysis::facts::panic::PanicAnalysisIncompleteIssue::from_reason(
        hostile.to_owned(),
    );
    issue.context = super::completeness_issue_context(root, hostile);
    super::project_completeness_report(
        inputs,
        presentation_range,
        request,
        root,
        vec![summary],
        issues,
    )
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

pub(in crate::cli::driver) fn root_preparation_artifact(
    functions: &[FunctionId],
) -> crate::analysis::facts::encoded::ArtifactFactIr {
    let callables = functions
        .iter()
        .enumerate()
        .map(|(ordinal, function)| {
            let path = format!("fixture::root_{ordinal}");
            CallableEntity::new(
                key(*function),
                path.clone(),
                false,
                true,
                true,
                false,
                vec![path],
            )
        })
        .collect();
    let bodies = functions
        .iter()
        .enumerate()
        .map(|(ordinal, function)| {
            CollectedFunctionBody::new(
                FunctionEntity::new(
                    key(*function),
                    format!("fixture::root_{ordinal}"),
                    FunctionBodyProvenance::DefiningArtifact,
                ),
                None,
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )
        })
        .collect();
    let program = CollectedProgram::try_new(Vec::new(), Vec::new(), callables, bodies)
        .expect("valid root-preparation program");
    let artifact = CollectedArtifact::try_new(CollectedArtifactInput {
        program,
        unsafe_operations: Vec::new(),
        panic_contracts: Vec::new(),
        safety_contracts: Vec::new(),
        mir_asserts: Vec::new(),
        marker_occurrences: Vec::new(),
    })
    .expect("valid root-preparation fixture");
    collect_artifact_facts(&artifact).expect("root-preparation fact collection succeeds")
}

fn foreign_consumer_overlay_artifact(
    function: FunctionId,
) -> crate::analysis::facts::encoded::ArtifactFactIr {
    let function_key = key(function);
    let path = String::from("dependency::instantiated");
    let program = CollectedProgram::try_new(
        Vec::new(),
        Vec::new(),
        vec![CallableEntity::new(
            function_key,
            path.clone(),
            false,
            true,
            true,
            false,
            vec![path.clone()],
        )],
        vec![CollectedFunctionBody::new(
            FunctionEntity::new(
                function_key,
                path,
                FunctionBodyProvenance::ConsumerInstantiation {
                    consumer_stable_crate_id: LOCAL_CRATE,
                },
            ),
            None,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )],
    )
    .expect("valid foreign consumer-overlay program");
    let artifact = CollectedArtifact::try_new(CollectedArtifactInput {
        program,
        unsafe_operations: Vec::new(),
        panic_contracts: Vec::new(),
        safety_contracts: Vec::new(),
        mir_asserts: Vec::new(),
        marker_occurrences: Vec::new(),
    })
    .expect("valid foreign consumer-overlay fixture");
    collect_artifact_facts(&artifact).expect("foreign consumer-overlay fact collection succeeds")
}

fn legacy_root_preparation_artifact(functions: &[FunctionId]) -> ArtifactAnalysisIr {
    let functions = functions
        .iter()
        .enumerate()
        .map(|(ordinal, function)| {
            let path = format!("fixture::root_{ordinal}");
            FunctionBodyIr {
                function: *function,
                provenance: FunctionBodyProvenanceIr::DefiningArtifact,
                display_path: path.clone(),
                attributes: FunctionAttributesIr {
                    is_unsafe: false,
                    is_exported: true,
                    has_rust_body: true,
                    is_foreign: false,
                    namespace_candidates: vec![path],
                },
                source_range: None,
                calls: Vec::new(),
                effects: Vec::new(),
                markers: Vec::new(),
            }
        })
        .collect();
    ArtifactAnalysisIr::new(functions, Vec::new()).expect("valid legacy root-preparation fixture")
}

fn range(byte_start: u64, byte_end: u64) -> SourceRangeIr {
    SourceRangeIr {
        file: SourceFileId::new("fixture-file"),
        byte_start,
        byte_end,
    }
}

fn assert_site(function: FunctionKey, basic_block: usize) -> EffectSiteKey {
    EffectSiteKey::from_mir(
        function,
        MirBodyLocation {
            basic_block,
            statement_index: 0,
        },
    )
    .expect("fixture MIR coordinate fits the permanent key")
}

#[allow(
    clippy::too_many_lines,
    reason = "the collected fixture keeps inherited assertion ownership and hostile owner variation together"
)]
fn ambiguous_assert_marker_artifact(
    root: FunctionId,
    helper: FunctionId,
    conflicting_owner: bool,
) -> crate::analysis::facts::encoded::ArtifactFactIr {
    let root_key = key(root);
    let helper_key = key(helper);
    let call_site = CallSiteKey::new(root_key, 0);
    let occurrence = CallOccurrenceKey::new(root_key, 3);
    let call_group = SafetyEffectGroupKey::new(root_key, 0);
    let first_site = assert_site(helper_key, 0);
    let second_site = assert_site(helper_key, 1);
    let call_anchor = SourceAnchorKey::new("fixture-file", 10, 15);
    let first_anchor = SourceAnchorKey::new("fixture-file", 20, 25);
    let second_anchor = SourceAnchorKey::new("fixture-file", 30, 35);
    let marker_anchor = SourceAnchorKey::new("fixture-file", 90, 95);
    let marker_occurrence = MarkerOccurrenceKey::new(marker_anchor.clone(), None);
    let marker_claim = MarkerClaimEntity::new(
        MarkerClaimKey::new(
            marker_occurrence.clone(),
            DomainId::new("sniff-test.panic").unwrap(),
            0,
        ),
        EvidenceClaimSelector::Unnamed,
        "the propagated root marker proves both compiler assertions",
    );
    let direct_claim = conflicting_owner.then(|| {
        MarkerClaimEntity::new(
            MarkerClaimKey::new(
                marker_occurrence.clone(),
                DomainId::new("sniff-test.panic").unwrap(),
                1,
            ),
            EvidenceClaimSelector::Unnamed,
            "the same physical marker is also attached directly in the helper",
        )
    });
    let mut claims = vec![marker_claim.clone()];
    claims.extend(direct_claim.iter().cloned());
    let effect_candidates = direct_claim
        .as_ref()
        .map(|claim| {
            vec![CollectedEffectMarkerCandidate::new(
                first_site,
                claim.key().clone(),
                EffectSiteHasMarkerClaimCandidate::new(true, true),
            )]
        })
        .unwrap_or_default();
    let marker = CollectedMarkerOccurrence::new(
        MarkerOccurrenceEntity::new(marker_occurrence, Vec::new()),
        claims,
        Vec::new(),
        vec![CollectedMarkerCallCandidate::new(
            occurrence,
            marker_claim.key().clone(),
            CallOccurrenceHasMarkerClaimCandidate::new(true, true),
        )],
        effect_candidates,
        Vec::new(),
    );
    let effect = |site, anchor| {
        CollectedEffectSite::new(
            EffectSiteEntity::new(site),
            vec![CollectedEffectSourceAnchor::new(
                EffectSourceAnchorRole::Presentation,
                anchor,
            )],
            Vec::new(),
        )
    };
    let program = CollectedProgram::try_new(
        vec![SourceFileEntity::new(
            "fixture-file",
            "src/lib.rs",
            "sha256:typed-panic-call-fixture",
            256,
        )],
        [
            call_anchor.clone(),
            first_anchor.clone(),
            second_anchor.clone(),
            marker_anchor,
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
                    CallSiteEntity::new(call_site),
                    vec![CollectedCallOccurrence::new(
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
                            helper_key,
                        )],
                        Vec::new(),
                        vec![call_group],
                        vec![CollectedCallSourceAnchor::new(
                            CallSourceAnchorRole::Presentation,
                            call_anchor,
                        )],
                        Vec::new(),
                    )],
                )],
                vec![SafetyEffectGroupEntity::new(call_group)],
                Vec::new(),
            ),
            CollectedFunctionBody::new(
                FunctionEntity::new(
                    helper_key,
                    "fixture::helper",
                    FunctionBodyProvenance::DefiningArtifact,
                ),
                None,
                Vec::new(),
                Vec::new(),
                vec![
                    effect(first_site, first_anchor),
                    effect(second_site, second_anchor),
                ],
            ),
        ],
    )
    .expect("valid propagated compiler-assert program");
    let artifact = CollectedArtifact::try_new(CollectedArtifactInput {
        program,
        unsafe_operations: Vec::new(),
        panic_contracts: Vec::new(),
        safety_contracts: Vec::new(),
        mir_asserts: vec![
            CollectedMirAssert::new(first_site, MirAssertKind::BoundsCheck),
            CollectedMirAssert::new(second_site, MirAssertKind::DivisionByZero),
        ],
        marker_occurrences: vec![marker],
    })
    .expect("valid propagated compiler-assert artifact");
    collect_artifact_facts(&artifact).expect("compiler-assert collection succeeds")
}

#[allow(
    clippy::too_many_lines,
    reason = "the legacy fixture mirrors the complete propagated-assert source model"
)]
fn legacy_ambiguous_assert_marker_artifact(
    root: FunctionId,
    helper: FunctionId,
) -> ArtifactAnalysisIr {
    ArtifactAnalysisIr::new(
        vec![
            FunctionBodyIr {
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
                calls: vec![CallEdgeIr {
                    id: CallId::new(3),
                    call_site: CallSiteId::new(0),
                    kind: CallEdgeKindIr::DirectCall,
                    safety_effect_group: Some(SafetyEffectGroupId::new(0)),
                    requires_unsafe: false,
                    inside_builtin_unsafe: false,
                    source_range: Some(range(10, 15)),
                    expanded_range: Some(range(10, 15)),
                    macro_expansions: Vec::new(),
                    callee_range: None,
                    applicable_attribution: vec![
                        CallableAttributionIr::ErasureSites,
                        CallableAttributionIr::CallSites,
                    ],
                    callable_keys: Vec::new(),
                    source_target: None,
                    target: CallTargetIr::Function(FunctionTargetIr {
                        function: helper,
                        display_path: String::from("fixture::helper"),
                        attributes: FunctionAttributesIr {
                            is_unsafe: false,
                            is_exported: false,
                            has_rust_body: true,
                            is_foreign: false,
                            namespace_candidates: vec![String::from("fixture::helper")],
                        },
                        contracts: FunctionContractsIr::default(),
                    }),
                }],
                effects: Vec::new(),
                markers: vec![MarkerIr {
                    id: MarkerId::new(0),
                    identity: String::from("shared-assert-marker"),
                    kind: MarkerKindIr::PanicJustification,
                    source_range: Some(range(90, 95)),
                    target: MarkerTargetIr::Call(CallId::new(3)),
                    applicable_probing: vec![
                        MarkerProbingIr::SourceCallsite,
                        MarkerProbingIr::MacroDefinitionFirst,
                    ],
                    satisfactions: vec![MarkerSatisfactionIr {
                        requirement: None,
                        reason: String::from(
                            "the propagated root marker proves both compiler assertions",
                        ),
                    }],
                    requirements: Vec::new(),
                }],
            },
            FunctionBodyIr {
                function: helper,
                provenance: FunctionBodyProvenanceIr::DefiningArtifact,
                display_path: String::from("fixture::helper"),
                attributes: FunctionAttributesIr {
                    is_unsafe: false,
                    is_exported: false,
                    has_rust_body: true,
                    is_foreign: false,
                    namespace_candidates: vec![String::from("fixture::helper")],
                },
                source_range: Some(range(16, 19)),
                calls: Vec::new(),
                effects: vec![
                    EffectFactIr {
                        id: EffectId::new(0),
                        safety_effect_group: None,
                        source_range: Some(range(20, 25)),
                        expanded_range: Some(range(20, 25)),
                        macro_expansions: Vec::new(),
                        kind: EffectKindIr::CompilerAssert {
                            kind: CompilerAssertKind::BoundsCheck,
                        },
                    },
                    EffectFactIr {
                        id: EffectId::new(1),
                        safety_effect_group: None,
                        source_range: Some(range(30, 35)),
                        expanded_range: Some(range(30, 35)),
                        macro_expansions: Vec::new(),
                        kind: EffectKindIr::CompilerAssert {
                            kind: CompilerAssertKind::DivisionByZero,
                        },
                    },
                ],
                markers: Vec::new(),
            },
        ],
        vec![SourceFileIr {
            id: SourceFileId::new("fixture-file"),
            filename: String::from("src/lib.rs"),
            content_hash: String::from("sha256:typed-panic-call-fixture"),
            byte_len: 256,
        }],
    )
    .expect("valid legacy propagated compiler-assert artifact")
}

#[allow(
    clippy::too_many_lines,
    reason = "the fixture keeps both producer lanes and their source provenance explicit"
)]
fn ambiguous_mixed_lane_marker_artifact(
    root: FunctionId,
    documented: FunctionId,
) -> crate::analysis::facts::encoded::ArtifactFactIr {
    let root_key = key(root);
    let documented_key = key(documented);
    let call_site = CallSiteKey::new(root_key, 0);
    let occurrence = CallOccurrenceKey::new(root_key, 3);
    let call_group = SafetyEffectGroupKey::new(root_key, 0);
    let effect_site = assert_site(root_key, 0);
    let effect_anchor = SourceAnchorKey::new("fixture-file", 10, 15);
    let call_presentation = SourceAnchorKey::new("fixture-file", 20, 25);
    let call_expanded = SourceAnchorKey::new("fixture-file", 30, 35);
    let contract_anchor = SourceAnchorKey::new("fixture-file", 40, 45);
    let marker_anchor = SourceAnchorKey::new("fixture-file", 90, 95);
    let marker_occurrence = MarkerOccurrenceKey::new(marker_anchor.clone(), None);
    let assert_claim = MarkerClaimEntity::new(
        MarkerClaimKey::new(
            marker_occurrence.clone(),
            DomainId::new("sniff-test.panic").unwrap(),
            0,
        ),
        EvidenceClaimSelector::Unnamed,
        "the physical marker proves the local compiler assertion",
    );
    let call_claim = MarkerClaimEntity::new(
        MarkerClaimKey::new(
            marker_occurrence.clone(),
            DomainId::new("sniff-test.panic").unwrap(),
            1,
        ),
        EvidenceClaimSelector::Unnamed,
        "the physical marker also proves the macro-expanded documented call",
    );
    let marker = CollectedMarkerOccurrence::new(
        MarkerOccurrenceEntity::new(marker_occurrence, Vec::new()),
        vec![assert_claim.clone(), call_claim.clone()],
        Vec::new(),
        vec![CollectedMarkerCallCandidate::new(
            occurrence,
            call_claim.key().clone(),
            CallOccurrenceHasMarkerClaimCandidate::new(true, true),
        )],
        vec![CollectedEffectMarkerCandidate::new(
            effect_site,
            assert_claim.key().clone(),
            EffectSiteHasMarkerClaimCandidate::new(true, true),
        )],
        Vec::new(),
    );
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
        vec![call_group],
        vec![
            CollectedCallSourceAnchor::new(
                CallSourceAnchorRole::Presentation,
                call_presentation.clone(),
            ),
            CollectedCallSourceAnchor::new(CallSourceAnchorRole::Expanded, call_expanded.clone()),
        ],
        vec![CollectedCallMacroFrame::new(
            CallMacroExpansionEntity::new(
                CallMacroExpansionKey::new(occurrence, 0),
                expansion(20),
                definition(131),
                "fixture::documented_macro",
            ),
            Some(call_presentation.clone()),
        )],
    );
    let program = CollectedProgram::try_new(
        vec![SourceFileEntity::new(
            "fixture-file",
            "src/lib.rs",
            "sha256:typed-panic-call-fixture",
            256,
        )],
        [
            effect_anchor.clone(),
            call_presentation,
            call_expanded,
            contract_anchor.clone(),
            marker_anchor,
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
            vec![SafetyEffectGroupEntity::new(call_group)],
            vec![CollectedEffectSite::new(
                EffectSiteEntity::new(effect_site),
                vec![CollectedEffectSourceAnchor::new(
                    EffectSourceAnchorRole::Presentation,
                    effect_anchor,
                )],
                Vec::new(),
            )],
        )],
    )
    .expect("valid mixed call/assert program");
    let artifact = CollectedArtifact::try_new(CollectedArtifactInput {
        program,
        unsafe_operations: Vec::new(),
        panic_contracts: vec![CollectedPanicContract::new(
            documented_key,
            Some(contract_anchor),
            Vec::new(),
        )],
        safety_contracts: Vec::new(),
        mir_asserts: vec![CollectedMirAssert::new(
            effect_site,
            MirAssertKind::BoundsCheck,
        )],
        marker_occurrences: vec![marker],
    })
    .expect("valid mixed call/assert artifact");
    collect_artifact_facts(&artifact).expect("mixed call/assert collection succeeds")
}

fn legacy_ambiguous_mixed_lane_marker_artifact(
    root: FunctionId,
    documented: FunctionId,
) -> ArtifactAnalysisIr {
    let marker = |id, target| MarkerIr {
        id: MarkerId::new(id),
        identity: String::from("shared-mixed-lane-marker"),
        kind: MarkerKindIr::PanicJustification,
        source_range: Some(range(90, 95)),
        target,
        applicable_probing: vec![
            MarkerProbingIr::SourceCallsite,
            MarkerProbingIr::MacroDefinitionFirst,
        ],
        satisfactions: vec![MarkerSatisfactionIr {
            requirement: None,
            reason: String::from("the physical marker proves this panic obligation"),
        }],
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
            source_range: Some(range(5, 9)),
            calls: vec![CallEdgeIr {
                id: CallId::new(3),
                call_site: CallSiteId::new(0),
                kind: CallEdgeKindIr::DirectCall,
                safety_effect_group: Some(SafetyEffectGroupId::new(0)),
                requires_unsafe: false,
                inside_builtin_unsafe: false,
                source_range: Some(range(20, 25)),
                expanded_range: Some(range(30, 35)),
                macro_expansions: vec![MacroExpansionFrameIr {
                    macro_def: definition(131),
                    display_path: String::from("fixture::documented_macro"),
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
                            source_range: Some(range(40, 45)),
                            requirements: Vec::new(),
                        }),
                        safety: None,
                    },
                }),
            }],
            effects: vec![EffectFactIr {
                id: EffectId::new(0),
                safety_effect_group: None,
                source_range: Some(range(10, 15)),
                expanded_range: Some(range(10, 15)),
                macro_expansions: Vec::new(),
                kind: EffectKindIr::CompilerAssert {
                    kind: CompilerAssertKind::BoundsCheck,
                },
            }],
            markers: vec![
                marker(0, MarkerTargetIr::Effect(EffectId::new(0))),
                marker(1, MarkerTargetIr::Call(CallId::new(3))),
            ],
        }],
        vec![SourceFileIr {
            id: SourceFileId::new("fixture-file"),
            filename: String::from("src/lib.rs"),
            content_hash: String::from("sha256:typed-panic-call-fixture"),
            byte_len: 256,
        }],
    )
    .expect("valid legacy mixed call/assert artifact")
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
fn nested_artifact(
    root: FunctionId,
    helper: FunctionId,
    sink: FunctionId,
    sink_has_rust_body: bool,
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
                sink_has_rust_body,
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
                    CallSiteEntity::new(CallSiteKey::new(helper_key, 99)),
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
fn legacy_nested_artifact(
    root: FunctionId,
    helper: FunctionId,
    sink: FunctionId,
    sink_has_rust_body: bool,
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
    let call =
        |id, call_site, source, expanded, macro_expansions, target: CallTargetIr| -> CallEdgeIr {
            CallEdgeIr {
                id: CallId::new(id),
                call_site: CallSiteId::new(call_site),
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
        0,
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
        99,
        range(60, 65),
        range(70, 75),
        vec![MacroExpansionFrameIr {
            macro_def: definition(93),
            display_path: String::from("fixture::terminal_macro"),
            source_range: Some(range(60, 65)),
        }],
        target(sink, "fixture::sink", sink_has_rust_body),
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

#[allow(
    clippy::too_many_lines,
    reason = "the mixed fixture keeps source-order and context-order traps explicit"
)]
fn mixed_completeness_artifact(
    root: FunctionId,
    missing: FunctionId,
    deferred: FunctionId,
) -> crate::analysis::facts::encoded::ArtifactFactIr {
    let root_key = key(root);
    let missing_key = key(missing);
    let deferred_key = key(deferred);
    let missing_occurrence = CallOccurrenceKey::new(root_key, 7);
    let deferred_occurrence = CallOccurrenceKey::new(root_key, 8);
    let missing_group = SafetyEffectGroupKey::new(root_key, 0);
    let deferred_group = SafetyEffectGroupKey::new(root_key, 1);
    let make_call = |occurrence,
                     target,
                     group,
                     presentation: SourceAnchorKey,
                     expanded: SourceAnchorKey| {
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
                CollectedCallSourceAnchor::new(CallSourceAnchorRole::Presentation, presentation),
                CollectedCallSourceAnchor::new(CallSourceAnchorRole::Expanded, expanded),
            ],
            Vec::new(),
        )
    };
    let anchors = [
        SourceAnchorKey::new("fixture-file", 20, 25),
        SourceAnchorKey::new("fixture-file", 30, 35),
        SourceAnchorKey::new("fixture-file", 40, 45),
        SourceAnchorKey::new("fixture-file", 50, 55),
    ];
    let missing_call = make_call(
        missing_occurrence,
        missing_key,
        missing_group,
        anchors[0].clone(),
        anchors[1].clone(),
    );
    let deferred_call = make_call(
        deferred_occurrence,
        deferred_key,
        deferred_group,
        anchors[2].clone(),
        anchors[3].clone(),
    );
    let callable = |key, path: &str| {
        CallableEntity::new(key, path, false, true, true, false, vec![path.to_owned()])
    };
    let program = CollectedProgram::try_new(
        vec![SourceFileEntity::new(
            "fixture-file",
            "src/lib.rs",
            "sha256:typed-panic-call-fixture",
            128,
        )],
        anchors.into_iter().map(SourceAnchorEntity::new).collect(),
        vec![
            callable(root_key, "fixture::root"),
            callable(missing_key, "fixture::missing"),
            callable(deferred_key, "fixture::deferred"),
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
                    CallSiteEntity::new(CallSiteKey::new(root_key, 99)),
                    vec![deferred_call, missing_call],
                )],
                vec![
                    SafetyEffectGroupEntity::new(missing_group),
                    SafetyEffectGroupEntity::new(deferred_group),
                ],
                Vec::new(),
            ),
            CollectedFunctionBody::new(
                FunctionEntity::new(
                    deferred_key,
                    "fixture::deferred",
                    FunctionBodyProvenance::DefiningArtifact,
                ),
                None,
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
        ],
    )
    .expect("valid mixed completeness program");
    let artifact = CollectedArtifact::try_new(CollectedArtifactInput {
        program,
        unsafe_operations: Vec::new(),
        panic_contracts: Vec::new(),
        safety_contracts: Vec::new(),
        mir_asserts: Vec::new(),
        marker_occurrences: Vec::new(),
    })
    .expect("valid mixed completeness artifact");
    collect_artifact_facts(&artifact).expect("mixed completeness collection succeeds")
}

fn legacy_mixed_completeness_artifact(
    root: FunctionId,
    missing: FunctionId,
    deferred: FunctionId,
) -> ArtifactAnalysisIr {
    let attributes = |path: &str| FunctionAttributesIr {
        is_unsafe: false,
        is_exported: true,
        has_rust_body: true,
        is_foreign: false,
        namespace_candidates: vec![path.to_owned()],
    };
    let call = |id, target, path: &str, presentation, expanded| CallEdgeIr {
        id: CallId::new(id),
        call_site: CallSiteId::new(99),
        kind: CallEdgeKindIr::DirectCall,
        safety_effect_group: Some(SafetyEffectGroupId::new(id)),
        requires_unsafe: false,
        inside_builtin_unsafe: false,
        source_range: Some(presentation),
        expanded_range: Some(expanded),
        macro_expansions: Vec::new(),
        callee_range: None,
        applicable_attribution: vec![
            CallableAttributionIr::ErasureSites,
            CallableAttributionIr::CallSites,
        ],
        callable_keys: Vec::new(),
        source_target: None,
        target: CallTargetIr::Function(FunctionTargetIr {
            function: target,
            display_path: path.to_owned(),
            attributes: attributes(path),
            contracts: FunctionContractsIr::default(),
        }),
    };
    ArtifactAnalysisIr::new(
        vec![
            FunctionBodyIr {
                function: root,
                provenance: FunctionBodyProvenanceIr::DefiningArtifact,
                display_path: String::from("fixture::root"),
                attributes: attributes("fixture::root"),
                source_range: Some(range(5, 10)),
                calls: vec![
                    call(
                        8,
                        deferred,
                        "fixture::deferred",
                        range(40, 45),
                        range(50, 55),
                    ),
                    call(7, missing, "fixture::missing", range(20, 25), range(30, 35)),
                ],
                effects: Vec::new(),
                markers: Vec::new(),
            },
            FunctionBodyIr {
                function: deferred,
                provenance: FunctionBodyProvenanceIr::DefiningArtifact,
                display_path: String::from("fixture::deferred"),
                attributes: attributes("fixture::deferred"),
                source_range: Some(range(60, 65)),
                calls: Vec::new(),
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
    .expect("valid mixed legacy completeness artifact")
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

fn root_duplicate_contract_artifact(
    root: FunctionId,
) -> crate::analysis::facts::encoded::ArtifactFactIr {
    root_contract_artifact(
        root,
        root,
        FunctionBodyProvenance::DefiningArtifact,
        Some(vec![
            ("Ready", "the value is ready", 60, 65),
            ("READY", "the value remains ready", 70, 75),
        ]),
    )
}

fn root_contract_artifact(
    body_function: FunctionId,
    declaration_function: FunctionId,
    provenance: FunctionBodyProvenance,
    requirements: Option<Vec<(&str, &str, u64, u64)>>,
) -> crate::analysis::facts::encoded::ArtifactFactIr {
    let body_key = key(body_function);
    let declaration_key = key(declaration_function);
    let assertion_site = assert_site(body_key, 0);
    let assertion_anchor = SourceAnchorKey::new("fixture-file", 20, 25);
    let contract_anchor = SourceAnchorKey::new("fixture-file", 50, 55);
    let mut anchors = vec![assertion_anchor.clone()];
    let panic_contracts = requirements.map_or_else(Vec::new, |requirements| {
        anchors.push(contract_anchor.clone());
        let requirements = requirements
            .into_iter()
            .enumerate()
            .map(|(ordinal, (name, condition, start, end))| {
                let anchor = SourceAnchorKey::new("fixture-file", start, end);
                anchors.push(anchor.clone());
                PanicRequirement::new(
                    declaration_key,
                    u32::try_from(ordinal).unwrap(),
                    name,
                    condition,
                    Some(anchor),
                )
            })
            .collect();
        vec![CollectedPanicContract::new(
            declaration_key,
            Some(contract_anchor),
            requirements,
        )]
    });
    let mut callables = vec![CallableEntity::new(
        body_key,
        "fixture::root",
        false,
        true,
        true,
        false,
        vec![String::from("fixture::root")],
    )];
    if declaration_key != body_key {
        callables.push(CallableEntity::new(
            declaration_key,
            "fixture::root",
            false,
            true,
            true,
            false,
            vec![String::from("fixture::root")],
        ));
        callables.sort_by_key(|callable| *callable.key());
    }
    let program = CollectedProgram::try_new(
        vec![SourceFileEntity::new(
            "fixture-file",
            "src/lib.rs",
            "sha256:typed-panic-call-fixture",
            128,
        )],
        anchors.into_iter().map(SourceAnchorEntity::new).collect(),
        callables,
        vec![CollectedFunctionBody::new(
            FunctionEntity::new(body_key, "fixture::root", provenance),
            None,
            Vec::new(),
            Vec::new(),
            vec![CollectedEffectSite::new(
                EffectSiteEntity::new(assertion_site),
                vec![CollectedEffectSourceAnchor::new(
                    EffectSourceAnchorRole::Presentation,
                    assertion_anchor,
                )],
                Vec::new(),
            )],
        )],
    )
    .expect("valid root-contract duplicate program");
    let artifact = CollectedArtifact::try_new(CollectedArtifactInput {
        program,
        unsafe_operations: Vec::new(),
        panic_contracts,
        safety_contracts: Vec::new(),
        mir_asserts: vec![CollectedMirAssert::new(
            assertion_site,
            MirAssertKind::BoundsCheck,
        )],
        marker_occurrences: Vec::new(),
    })
    .expect("valid root-contract duplicate artifact");
    collect_artifact_facts(&artifact).expect("root-contract duplicate collection succeeds")
}

fn legacy_root_duplicate_contract_artifact(root: FunctionId) -> ArtifactAnalysisIr {
    legacy_root_contract_artifact(
        root,
        Some(vec![
            ("Ready", "the value is ready", 60, 65),
            ("READY", "the value remains ready", 70, 75),
        ]),
    )
}

fn legacy_root_contract_artifact(
    root: FunctionId,
    requirements: Option<Vec<(&str, &str, u64, u64)>>,
) -> ArtifactAnalysisIr {
    let marker = requirements.map(|requirements| MarkerIr {
        id: MarkerId::new(0),
        identity: String::from("root-panic-contract"),
        kind: MarkerKindIr::PanicContract,
        source_range: Some(range(50, 55)),
        target: MarkerTargetIr::Function(root),
        applicable_probing: vec![
            MarkerProbingIr::SourceCallsite,
            MarkerProbingIr::MacroDefinitionFirst,
        ],
        satisfactions: Vec::new(),
        requirements: requirements
            .into_iter()
            .map(|(name, condition, start, end)| ContractRequirementIr {
                name: name.to_owned(),
                condition: condition.to_owned(),
                source_range: Some(range(start, end)),
            })
            .collect(),
    });
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
            calls: Vec::new(),
            effects: vec![EffectFactIr {
                id: EffectId::new(0),
                safety_effect_group: None,
                source_range: Some(range(20, 25)),
                expanded_range: Some(range(20, 25)),
                macro_expansions: Vec::new(),
                kind: EffectKindIr::CompilerAssert {
                    kind: CompilerAssertKind::BoundsCheck,
                },
            }],
            markers: marker.into_iter().collect(),
        }],
        vec![SourceFileIr {
            id: SourceFileId::new("fixture-file"),
            filename: String::from("src/lib.rs"),
            content_hash: String::from("sha256:typed-panic-call-fixture"),
            byte_len: 128,
        }],
    )
    .expect("valid legacy root-contract duplicate fixture")
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
    documented_calls_artifact(root, first_documented, second_documented, false, false)
}

fn ambiguous_call_marker_artifact(
    root: FunctionId,
    first_documented: FunctionId,
    second_documented: FunctionId,
) -> crate::analysis::facts::encoded::ArtifactFactIr {
    documented_calls_artifact(root, first_documented, second_documented, true, false)
}

fn ambiguous_multi_claim_call_marker_artifact(
    root: FunctionId,
    first_documented: FunctionId,
    second_documented: FunctionId,
) -> crate::analysis::facts::encoded::ArtifactFactIr {
    documented_calls_artifact(root, first_documented, second_documented, true, true)
}

#[allow(
    clippy::too_many_lines,
    reason = "the shared fixture keeps the normal and ambiguity paths byte-for-byte comparable"
)]
fn documented_calls_artifact(
    root: FunctionId,
    first_documented: FunctionId,
    second_documented: FunctionId,
    ambiguous_marker: bool,
    multiple_claims: bool,
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
    let mut first_requirements = [
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
    .collect::<Vec<_>>();
    let mut second_requirements = vec![PanicRequirement::new(
        second_key,
        0,
        "Initialized",
        "the value is initialized",
        Some(second_requirement_anchor.clone()),
    )];
    let marker_occurrence = MarkerOccurrenceKey::new(marker_anchor.clone(), None);
    if ambiguous_marker {
        first_requirements.clear();
        second_requirements.clear();
    }
    let marker_claim = MarkerClaimEntity::new(
        MarkerClaimKey::new(
            marker_occurrence.clone(),
            DomainId::new("sniff-test.panic").unwrap(),
            0,
        ),
        if ambiguous_marker {
            EvidenceClaimSelector::Unnamed
        } else {
            EvidenceClaimSelector::Named(String::from("ready"))
        },
        if ambiguous_marker {
            "fixture proves both unnamed call groups"
        } else {
            "fixture proves only the ready requirement group"
        },
    );
    let second_marker_claim = multiple_claims.then(|| {
        MarkerClaimEntity::new(
            MarkerClaimKey::new(
                marker_occurrence.clone(),
                DomainId::new("sniff-test.panic").unwrap(),
                1,
            ),
            EvidenceClaimSelector::Unnamed,
            "the second physical-marker claim proves the second unnamed call group",
        )
    });
    let nonmatching_marker_claim = multiple_claims.then(|| {
        MarkerClaimEntity::new(
            MarkerClaimKey::new(
                marker_occurrence.clone(),
                DomainId::new("sniff-test.panic").unwrap(),
                2,
            ),
            EvidenceClaimSelector::Named(String::from("does-not-exist")),
            "this active call claim deliberately matches no unnamed obligation",
        )
    });
    let mut call_candidates = vec![CollectedMarkerCallCandidate::new(
        first_occurrence,
        marker_claim.key().clone(),
        CallOccurrenceHasMarkerClaimCandidate::new(true, true),
    )];
    if ambiguous_marker {
        call_candidates.push(CollectedMarkerCallCandidate::new(
            second_occurrence,
            second_marker_claim
                .as_ref()
                .map_or_else(|| marker_claim.key().clone(), |claim| claim.key().clone()),
            CallOccurrenceHasMarkerClaimCandidate::new(true, true),
        ));
    }
    if let Some(claim) = &nonmatching_marker_claim {
        call_candidates.push(CollectedMarkerCallCandidate::new(
            first_occurrence,
            claim.key().clone(),
            CallOccurrenceHasMarkerClaimCandidate::new(true, true),
        ));
    }
    let mut marker_claims = vec![marker_claim];
    marker_claims.extend(second_marker_claim);
    marker_claims.extend(nonmatching_marker_claim);
    let marker = CollectedMarkerOccurrence::new(
        MarkerOccurrenceEntity::new(marker_occurrence, Vec::new()),
        marker_claims,
        Vec::new(),
        call_candidates,
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
    legacy_documented_calls_artifact(root, first_documented, second_documented, false)
}

fn legacy_ambiguous_call_marker_artifact(
    root: FunctionId,
    first_documented: FunctionId,
    second_documented: FunctionId,
) -> ArtifactAnalysisIr {
    legacy_documented_calls_artifact(root, first_documented, second_documented, true)
}

#[allow(
    clippy::too_many_lines,
    reason = "the shared legacy fixture mirrors both permanent ambiguity modes"
)]
fn legacy_documented_calls_artifact(
    root: FunctionId,
    first_documented: FunctionId,
    second_documented: FunctionId,
    ambiguous_marker: bool,
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
    let first_requirements = if ambiguous_marker {
        Vec::new()
    } else {
        requirements(&[
            ("Ready", "the value is ready", 50, 55),
            ("READY", "the value remains ready", 60, 65),
            ("Index_In-Bounds", "the index is valid", 70, 75),
            ("index-in_bounds", "the index remains valid", 80, 85),
        ])
    };
    let second_requirements = if ambiguous_marker {
        Vec::new()
    } else {
        requirements(&[("Initialized", "the value is initialized", 150, 155)])
    };
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
            markers: [3_u32, 4]
                .into_iter()
                .take(if ambiguous_marker { 2 } else { 1 })
                .enumerate()
                .map(|(index, call)| MarkerIr {
                    id: MarkerId::new(u32::try_from(index).unwrap()),
                    identity: if ambiguous_marker {
                        String::from("shared-unnamed-marker")
                    } else {
                        String::from("ready-marker")
                    },
                    kind: MarkerKindIr::PanicJustification,
                    source_range: Some(range(90, 95)),
                    target: MarkerTargetIr::Call(CallId::new(call)),
                    applicable_probing: vec![
                        MarkerProbingIr::SourceCallsite,
                        MarkerProbingIr::MacroDefinitionFirst,
                    ],
                    satisfactions: vec![MarkerSatisfactionIr {
                        requirement: (!ambiguous_marker).then(|| String::from("ready")),
                        reason: if ambiguous_marker {
                            String::from("fixture proves both unnamed call groups")
                        } else {
                            String::from("fixture proves only the ready requirement group")
                        },
                    }],
                    requirements: Vec::new(),
                })
                .collect(),
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

struct UnavailableSources;

impl FindingSources for UnavailableSources {
    fn function_span(&self, _function: FunctionId) -> Option<Span> {
        None
    }

    fn resolve(&self, range: Option<&SourceRangeIr>) -> (Option<Span>, Option<String>) {
        match range {
            Some(_) => (None, Some(String::from("fixture source unavailable"))),
            None => (None, None),
        }
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

fn assert_root_contract_finding_parity(
    report: &super::TypedPanicRootContractRootReport,
    legacy: &ArtifactAnalysisIr,
    request: &InterpretationRoot,
    config: &SniffTestConfig,
) {
    let legacy = interpret(legacy, std::slice::from_ref(request), config);
    let sources = FixtureSources {
        root: request.function,
        file: SourceFileIr {
            id: SourceFileId::new("fixture-file"),
            filename: String::from("src/lib.rs"),
            content_hash: String::from("sha256:typed-panic-call-fixture"),
            byte_len: 128,
        },
    };
    for show_full_stack_trace in [false, true] {
        let expected = legacy[0]
            .findings
            .iter()
            .map(|finding| {
                adapt_typed_panic_call_finding(&sources, request, finding, show_full_stack_trace)
            })
            .collect::<Vec<_>>();
        let actual = adapt_typed_panic_root_contract_reports(
            &sources,
            vec![report.clone()],
            std::slice::from_ref(request),
            show_full_stack_trace,
        )
        .expect("the owned root-contract report adapts atomically");
        assert_eq!(actual, expected);

        let expected_degraded = legacy[0]
            .findings
            .iter()
            .map(|finding| {
                adapt_typed_panic_call_finding(
                    &UnavailableSources,
                    request,
                    finding,
                    show_full_stack_trace,
                )
            })
            .collect::<Vec<_>>();
        let actual_degraded = adapt_typed_panic_root_contract_reports(
            &UnavailableSources,
            vec![report.clone()],
            std::slice::from_ref(request),
            show_full_stack_trace,
        )
        .expect("unavailable root-contract sources degrade through the legacy boundary");
        assert_eq!(actual_degraded, expected_degraded);
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
    let (mixed, _, mixed_fixture) = evaluate_typed_panic_call_with_projection_fixture(
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
    let (sink, _, sink_fixture) = evaluate_typed_panic_call_with_projection_fixture(
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
fn call_projection_rejects_missing_and_duplicate_issue_rows() {
    let root_function = function(75);
    let facts = sink_artifact(root_function, exact_function(76));
    let requested_root = root(root_function);
    let mut config = SniffTestConfig::default();
    config.panics.panic_sink_namespaces =
        PathPatterns::new(vec![String::from("fixture::sink")]).unwrap();
    let (report, _, fixture) = evaluate_typed_panic_call_with_projection_fixture(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        [],
        &[],
        &requested_root,
        &config,
    )
    .expect("sink projection fixture evaluates");
    let [issue] = fixture.unsatisfied.as_slice() else {
        panic!("the sink fixture emits one unsatisfied issue");
    };
    let obligations =
        super::index_obligations(&fixture.inputs, &report.root, fixture.obligations.clone())
            .expect("fixture obligations are canonical");
    let matches =
        super::validate_call_match_rows(&report.root, &obligations, fixture.matches.clone())
            .expect("fixture matches are canonical");
    let projector = super::PanicCallTraceProjector::prepare(&fixture.inputs)
        .expect("fixture call traces project");

    let mut duplicate = fixture.unsatisfied.clone();
    duplicate.push(issue.clone());
    for (name, unsatisfied) in [("missing", Vec::new()), ("duplicate", duplicate)] {
        assert!(
            super::project_root_report(
                &fixture.inputs,
                report.presentation_range.clone(),
                &requested_root,
                &report.root,
                super::PanicCallProjectionRows {
                    obligations: &obligations,
                    matches: &matches,
                    projector: &projector,
                    unsatisfied,
                    duplicates: fixture.duplicates.clone(),
                },
            )
            .is_err(),
            "call projection accepted {name} issue rows"
        );
    }
}

#[test]
fn call_projection_rejects_missing_and_duplicate_requirement_issue_rows() {
    let root_function = function(77);
    let facts = mixed_documented_artifact(root_function, exact_function(78), exact_function(79));
    let requested_root = root(root_function);
    let (report, _, fixture) = evaluate_typed_panic_call_with_projection_fixture(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        [],
        &[],
        &requested_root,
        &SniffTestConfig::default(),
    )
    .expect("documented projection fixture evaluates");
    let first = fixture
        .duplicates
        .first()
        .expect("the documented fixture emits duplicate requirements")
        .clone();
    let obligations =
        super::index_obligations(&fixture.inputs, &report.root, fixture.obligations.clone())
            .expect("fixture obligations are canonical");
    let matches =
        super::validate_call_match_rows(&report.root, &obligations, fixture.matches.clone())
            .expect("fixture matches are canonical");
    let projector = super::PanicCallTraceProjector::prepare(&fixture.inputs)
        .expect("fixture call traces project");

    let mut missing = fixture.duplicates.clone();
    missing.remove(0);
    let mut duplicate = fixture.duplicates.clone();
    duplicate.push(first);
    for (name, duplicates) in [("missing", missing), ("duplicate", duplicate)] {
        assert!(
            super::project_root_report(
                &fixture.inputs,
                report.presentation_range.clone(),
                &requested_root,
                &report.root,
                super::PanicCallProjectionRows {
                    obligations: &obligations,
                    matches: &matches,
                    projector: &projector,
                    unsatisfied: fixture.unsatisfied.clone(),
                    duplicates,
                },
            )
            .is_err(),
            "call projection accepted {name} duplicate-requirement rows"
        );
    }
}

#[test]
fn issue_validators_reject_cross_witness_and_hostile_context_joins() {
    let root_function = function(80);
    let facts = mixed_documented_artifact(root_function, exact_function(81), exact_function(82));
    let requested_root = root(root_function);
    let (report, _, fixture) = evaluate_typed_panic_call_with_projection_fixture(
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
    let facts = nested_artifact(root_function, helper_function, sink_function, false);
    let legacy = legacy_nested_artifact(root_function, helper_function, sink_function, false);
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

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one parity test freezes the silent boundary, raw issue, and report-v14 projection"
)]
fn root_contract_duplicate_requirements_have_exact_legacy_parity() {
    let root_function = function(143);
    let facts = root_duplicate_contract_artifact(root_function);
    let legacy = legacy_root_duplicate_contract_artifact(root_function);
    let requested_root = root(root_function);

    let batch = super::evaluate_typed_panic_call_roots(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        &[],
        Vec::new(),
        &[],
        std::slice::from_ref(&requested_root),
        &SniffTestConfig::default(),
    )
    .expect("root-contract duplicate evaluation succeeds");
    let [report] = batch.root_contracts.as_slice() else {
        panic!("one requested root must retain one owned root-contract report");
    };
    let [issue] = report.issues.as_slice() else {
        panic!("the root contract has one normalized duplicate requirement group");
    };
    assert!(batch.compiler_asserts[0].issues.is_empty());
    assert!(batch.roots[0].issues.is_empty());
    assert_eq!(issue.function, root_function);
    assert_eq!(issue.function_path, "fixture::root");
    assert_eq!(issue.source_range, Some(range(50, 55)));
    assert_eq!(issue.normalized_name, "ready");
    assert_eq!(
        issue
            .requirements
            .iter()
            .map(|requirement| (
                requirement.ordinal,
                requirement.name.as_str(),
                requirement.source_range.as_ref().unwrap().byte_start,
            ))
            .collect::<Vec<_>>(),
        [(0, "Ready", 60), (1, "READY", 70)]
    );

    let (_, _, fixture) = evaluate_typed_panic_call_with_projection_fixture(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        [],
        &[],
        &requested_root,
        &SniffTestConfig::default(),
    )
    .expect("the opt-in fixture exposes the raw root-contract issue");
    assert_eq!(fixture.inputs.call_count(), 0);
    assert!(fixture.inputs.compiler_asserts().assertions().is_empty());
    assert!(fixture.obligations.is_empty());
    assert_eq!(fixture.root_contract_duplicates.len(), 1);
    let traversal = fixture.inputs.traversal();
    let [boundary] = traversal.body_boundaries() else {
        panic!("the whole traversal must be one root-contract boundary");
    };
    assert_eq!(boundary.order(), 0);
    assert_eq!(boundary.body().erase(), fixture.inputs.root().entity);
    assert!(boundary.trace().relations().is_empty());
    assert!(traversal.body_visits().is_empty());
    assert!(traversal.effect_visits().is_empty());
    assert!(traversal.unsafe_operation_visits().is_empty());
    assert!(traversal.occurrence_visits().is_empty());
    assert!(traversal.callable_resolutions().is_empty());
    assert!(traversal.consumer_body_sources().is_empty());
    assert!(traversal.consumer_reconciliations().is_empty());
    assert!(traversal.followed_calls().is_empty());
    assert!(traversal.call_boundaries().is_empty());
    assert!(traversal.outcomes().is_empty());

    let legacy = interpret(
        &legacy,
        std::slice::from_ref(&requested_root),
        &SniffTestConfig::default(),
    );
    let [legacy_finding] = legacy[0].findings.as_slice() else {
        panic!("legacy root_is_boundary emits one duplicate requirement finding");
    };
    assert!(matches!(
        legacy_finding.kind,
        InterpretedFindingKind::AmbiguousPanicRequirement { ref normalized_name }
            if normalized_name == "ready"
    ));
    assert!(legacy_finding.target.is_none());
    assert!(legacy_finding.trace.steps.is_empty());

    let sources = FixtureSources {
        root: root_function,
        file: SourceFileIr {
            id: SourceFileId::new("fixture-file"),
            filename: String::from("src/lib.rs"),
            content_hash: String::from("sha256:typed-panic-call-fixture"),
            byte_len: 128,
        },
    };
    for show_full_stack_trace in [false, true] {
        let expected = adapt_typed_panic_call_finding(
            &sources,
            &requested_root,
            legacy_finding,
            show_full_stack_trace,
        );
        let actual = adapt_typed_panic_root_contract_reports(
            &sources,
            batch.root_contracts.clone(),
            std::slice::from_ref(&requested_root),
            show_full_stack_trace,
        )
        .expect("the owned root-contract report adapts atomically");
        assert_eq!(actual.as_slice(), std::slice::from_ref(&expected));
        let authority = adapt_typed_panic_authority_batch(
            &sources,
            batch.clone(),
            std::slice::from_ref(&requested_root),
            show_full_stack_trace,
        )
        .expect("the unified authority preserves the targetless root-contract finding");
        assert_eq!(authority, [expected]);
        assert_eq!(authority[0].kind, FindingKind::AmbiguousPanicRequirement);
        assert!(authority[0].target.is_none());
        assert!(authority[0].trace.is_empty());

        let expected_degraded = adapt_typed_panic_call_finding(
            &UnavailableSources,
            &requested_root,
            legacy_finding,
            show_full_stack_trace,
        );
        let actual_degraded = adapt_typed_panic_root_contract_reports(
            &UnavailableSources,
            batch.root_contracts.clone(),
            std::slice::from_ref(&requested_root),
            show_full_stack_trace,
        )
        .expect("unavailable root-contract source degrades through the legacy boundary");
        assert_eq!(
            actual_degraded.as_slice(),
            std::slice::from_ref(&expected_degraded)
        );
        let authority_degraded = adapt_typed_panic_authority_batch(
            &UnavailableSources,
            batch.clone(),
            std::slice::from_ref(&requested_root),
            show_full_stack_trace,
        )
        .expect("the unified authority degrades the targetless root-contract finding");
        assert_eq!(authority_degraded, [expected_degraded]);
        assert_eq!(
            authority_degraded[0].kind,
            FindingKind::AmbiguousPanicRequirement
        );
        assert!(authority_degraded[0].target.is_none());
        assert!(authority_degraded[0].trace.is_empty());
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one policy test freezes replacement, removal, provenance, ordering, and parity"
)]
fn override_root_contract_preserves_lexical_groups_and_declaration_members() {
    let root_function = function(146);
    let facts = root_duplicate_contract_artifact(root_function);
    let legacy = legacy_root_duplicate_contract_artifact(root_function);
    let requested_root = root(root_function);
    let mut config = SniffTestConfig::default();
    config.documentation.overrides = ContractDocOverrides::new(vec![(
        String::from("fixture::root"),
        String::from("# Panics\n- zeta: first\n- alpha: second\n- zeta: third\n- alpha: fourth"),
    )])
    .unwrap();

    let batch = super::evaluate_typed_panic_call_roots(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        &[],
        Vec::new(),
        &[],
        std::slice::from_ref(&requested_root),
        &config,
    )
    .expect("override root-contract evaluation succeeds");
    let [report] = batch.root_contracts.as_slice() else {
        panic!("one requested root retains one override report");
    };
    assert_eq!(report.selected_function, Some(root_function));
    assert_eq!(report.selected_path.as_deref(), Some("fixture::root"));
    assert_eq!(
        report
            .issues
            .iter()
            .map(|issue| (
                issue.normalized_name.as_str(),
                issue
                    .requirements
                    .iter()
                    .map(|requirement| requirement.condition.as_str())
                    .collect::<Vec<_>>(),
            ))
            .collect::<Vec<_>>(),
        [
            ("alpha", vec!["second", "fourth"]),
            ("zeta", vec!["first", "third"]),
        ]
    );
    assert!(report.issues.iter().all(|issue| {
        issue.source_range.is_none()
            && issue
                .requirements
                .iter()
                .all(|requirement| requirement.source_range.is_none())
    }));

    let (_, _, fixture) = evaluate_typed_panic_call_with_projection_fixture(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        [],
        &[],
        &requested_root,
        &config,
    )
    .expect("override raw projection fixture evaluates");
    let boundary = super::root_contract_boundary(&fixture.inputs)
        .unwrap()
        .expect("override retains a root boundary");
    let contract = super::root_contract(boundary).unwrap();
    assert_eq!(
        contract.origin(),
        crate::analysis::facts::panic::EffectivePanicContractOrigin::Override
    );
    assert!(contract.raw_contract().is_none());
    assert!(contract.source_anchor().is_none());
    assert_eq!(
        fixture
            .root_contract_duplicates
            .iter()
            .map(|row| (
                row.data.normalized_name(),
                row.data.requirement_ordinals(),
                row.context.source.as_ref(),
            ))
            .collect::<Vec<_>>(),
        [("alpha", &[1, 3][..], None), ("zeta", &[0, 2][..], None)]
    );
    assert_root_contract_finding_parity(report, &legacy, &requested_root, &config);

    let mut removing_config = SniffTestConfig::default();
    removing_config.documentation.overrides = ContractDocOverrides::new(vec![(
        String::from("fixture::root"),
        String::from("# Notes\nThe override intentionally removes the panic contract."),
    )])
    .unwrap();
    let removed = super::evaluate_typed_panic_call_roots(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        &[],
        Vec::new(),
        &[],
        std::slice::from_ref(&requested_root),
        &removing_config,
    )
    .expect("an override without # Panics removes the raw root contract");
    assert!(removed.root_contracts[0].selected_function.is_none());
    assert!(removed.root_contracts[0].selected_path.is_none());
    assert!(removed.root_contracts[0].issues.is_empty());
    assert!(
        interpret(
            &legacy,
            std::slice::from_ref(&requested_root),
            &removing_config,
        )[0]
        .findings
        .iter()
        .all(|finding| !matches!(
            finding.kind,
            InterpretedFindingKind::AmbiguousPanicRequirement { .. }
        ))
    );
}

#[test]
fn raw_generic_contract_keeps_exact_selected_body_and_generic_declaration() {
    let declaration = function(147);
    let selected = exact_function(147);
    let facts = root_contract_artifact(
        selected,
        declaration,
        FunctionBodyProvenance::DefiningArtifact,
        Some(vec![
            ("Ready", "the value is ready", 60, 65),
            ("READY", "the value remains ready", 70, 75),
        ]),
    );
    let legacy = legacy_root_duplicate_contract_artifact(selected);
    let requested_root = InterpretationRoot {
        function: selected,
        path: String::from("fixture::root"),
        kind: ReportRootKind::Concrete,
    };

    let batch = super::evaluate_typed_panic_call_roots(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        &[],
        Vec::new(),
        &[],
        std::slice::from_ref(&requested_root),
        &SniffTestConfig::default(),
    )
    .expect("raw-generic root-contract evaluation succeeds");
    let [report] = batch.root_contracts.as_slice() else {
        panic!("one exact request retains one root-contract report");
    };
    assert_eq!(report.function, selected);
    assert_eq!(report.selected_function, Some(selected));
    assert_eq!(report.issues[0].function, selected);

    let (_, _, fixture) = evaluate_typed_panic_call_with_projection_fixture(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        [],
        &[],
        &requested_root,
        &SniffTestConfig::default(),
    )
    .expect("raw-generic projection fixture evaluates");
    let boundary = super::root_contract_boundary(&fixture.inputs)
        .unwrap()
        .expect("raw-generic contract retains a root boundary");
    let contract = super::root_contract(boundary).unwrap();
    assert_eq!(*boundary.body_data().key(), key(selected));
    assert_eq!(
        contract.origin(),
        crate::analysis::facts::panic::EffectivePanicContractOrigin::RawGeneric
    );
    assert_eq!(
        fixture.root_contract_callable_keys,
        Some((key(selected), key(declaration)))
    );
    assert_eq!(contract.queried_callable(), boundary.callable());
    assert_ne!(contract.queried_callable(), contract.declaration_owner());
    assert!(contract.raw_contract().is_some());
    let [row] = fixture.root_contract_duplicates.as_slice() else {
        panic!("raw-generic duplicate contract emits exactly one issue row");
    };
    assert_eq!(row.context.root, *fixture.inputs.root());
    assert_eq!(row.context.source.as_ref(), contract.raw_contract());
    assert_eq!(
        row.context.endpoint.as_ref(),
        Some(&boundary.body().erase())
    );
    assert_eq!(row.context.trace.as_ref(), Some(boundary.trace()));
    assert_eq!(boundary.trace().root(), &fixture.inputs.root().entity);
    assert_eq!(boundary.trace().target(), &fixture.inputs.root().entity);
    assert!(boundary.trace().relations().is_empty());
    assert_root_contract_finding_parity(
        report,
        &legacy,
        &requested_root,
        &SniffTestConfig::default(),
    );
}

#[test]
fn exact_request_to_generic_body_fallback_preserves_both_public_identities() {
    let selected = function(148);
    let requested = exact_function(148);
    let facts = root_duplicate_contract_artifact(selected);
    let legacy = legacy_root_duplicate_contract_artifact(selected);
    let requested_root = InterpretationRoot {
        function: requested,
        path: String::from("fixture::root::<u8>"),
        kind: ReportRootKind::Concrete,
    };

    let batch = super::evaluate_typed_panic_call_roots(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        &[],
        Vec::new(),
        &[],
        std::slice::from_ref(&requested_root),
        &SniffTestConfig::default(),
    )
    .expect("generic-body fallback root-contract evaluation succeeds");
    let [preparation] = batch.root_preparations.as_slice() else {
        panic!("one exact request retains one preparation row");
    };
    assert_eq!(preparation.request_ordinal, 0);
    assert_eq!(preparation.request, requested_root);
    assert_eq!(preparation.requested_function, key(requested));
    assert_eq!(
        preparation.expected_scope,
        crate::analysis::facts::workspace::ArtifactScopeId::for_in_memory(LOCAL_CRATE, 0)
    );
    assert!(matches!(
        preparation.outcome,
        super::TypedPanicRootPreparationOutcome::Evaluatable {
            report_index: 0,
            ..
        }
    ));
    let super::TypedPanicRootPreparationOutcome::Evaluatable {
        root: prepared_root,
        selected_function,
        ..
    } = &preparation.outcome
    else {
        unreachable!("the exact request is evaluatable");
    };
    assert_eq!(*selected_function, key(selected));
    let [report] = batch.root_contracts.as_slice() else {
        panic!("one exact request retains one fallback root-contract report");
    };
    assert_eq!(prepared_root, &report.root);
    assert_eq!(report.function, requested);
    assert_eq!(report.path, "fixture::root::<u8>");
    assert_eq!(report.kind, ReportRootKind::Concrete);
    assert_eq!(report.selected_function, Some(selected));
    assert_eq!(report.selected_path.as_deref(), Some("fixture::root"));
    assert_eq!(report.issues[0].function, selected);
    assert_eq!(report.issues[0].function_path, "fixture::root");
    let interpreted = interpret(
        &legacy,
        std::slice::from_ref(&requested_root),
        &SniffTestConfig::default(),
    );
    assert_eq!(interpreted[0].findings[0].function, selected);
    assert_eq!(interpreted[0].findings[0].function_path, "fixture::root");
    assert_root_contract_finding_parity(
        report,
        &legacy,
        &requested_root,
        &SniffTestConfig::default(),
    );

    let mut hostile_function = batch.clone();
    hostile_function.root_contracts[0].selected_function = Some(requested);
    for issue in &mut hostile_function.root_contracts[0].issues {
        issue.function = requested;
    }
    let mut hostile_path = batch;
    hostile_path.root_contracts[0].selected_path = Some(String::from("fixture::forged"));
    for issue in &mut hostile_path.root_contracts[0].issues {
        issue.function_path = String::from("fixture::forged");
    }
    for (name, hostile) in [
        ("selected function", hostile_function),
        ("selected path", hostile_path),
    ] {
        let sources = CountingSources::default();
        let result = adapt_typed_panic_authority_batch(
            &sources,
            hostile,
            std::slice::from_ref(&requested_root),
            true,
        );
        assert!(result.is_err(), "a forged root-contract {name} must reject");
        assert_eq!(sources.calls.get(), 0, "{name} consulted sources");
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one policy matrix keeps no-contract, ignored, trusted, empty, and unique roots aligned"
)]
fn root_contract_policy_precedence_and_silent_empty_reports_are_aligned() {
    let plain_root = function(149);
    let plain_facts = sink_artifact(plain_root, exact_function(150));
    let plain_request = root(plain_root);
    let plain = super::evaluate_typed_panic_call_roots(
        TypedPanicLocalArtifact::in_memory(&plain_facts, LOCAL_CRATE),
        &[],
        Vec::new(),
        &[],
        std::slice::from_ref(&plain_request),
        &SniffTestConfig::default(),
    )
    .expect("ordinary root evaluation succeeds");
    assert!(matches!(
        plain.root_contracts.as_slice(),
        [report]
            if report.function == plain_request.function
                && report.path == plain_request.path
                && report.kind == plain_request.kind
                && report.selected_function.is_none()
                && report.selected_path.is_none()
                && report.issues.is_empty()
    ));

    let ignored_root = function(151);
    let ignored_facts = root_duplicate_contract_artifact(ignored_root);
    let ignored_legacy = legacy_root_duplicate_contract_artifact(ignored_root);
    let ignored_request = root(ignored_root);
    let mut ignored_config = SniffTestConfig::default();
    ignored_config.panics.ignored_namespaces =
        PathPatterns::new(vec![String::from("fixture::root")]).unwrap();
    let ignored = super::evaluate_typed_panic_call_roots(
        TypedPanicLocalArtifact::in_memory(&ignored_facts, LOCAL_CRATE),
        &[],
        Vec::new(),
        &[],
        std::slice::from_ref(&ignored_request),
        &ignored_config,
    )
    .expect("ignored duplicate root evaluation succeeds");
    let [ignored_report] = ignored.root_contracts.as_slice() else {
        panic!("ignored root still returns one aligned root-contract report");
    };
    assert_eq!(ignored_report.function, ignored_request.function);
    assert_eq!(ignored_report.path, ignored_request.path);
    assert_eq!(ignored_report.kind, ignored_request.kind);
    assert!(ignored_report.selected_function.is_none());
    assert!(ignored_report.selected_path.is_none());
    assert!(ignored_report.issues.is_empty());
    assert!(ignored.roots[0].issues.is_empty());
    assert!(
        interpret(
            &ignored_legacy,
            std::slice::from_ref(&ignored_request),
            &ignored_config,
        )[0]
        .findings
        .is_empty()
    );
    let (_, _, ignored_fixture) = evaluate_typed_panic_call_with_projection_fixture(
        TypedPanicLocalArtifact::in_memory(&ignored_facts, LOCAL_CRATE),
        [],
        &[],
        &ignored_request,
        &ignored_config,
    )
    .expect("ignored projection fixture evaluates");
    assert_eq!(ignored_fixture.inputs.call_count(), 0);
    assert!(
        ignored_fixture
            .inputs
            .compiler_asserts()
            .assertions()
            .is_empty()
    );
    assert!(ignored_fixture.root_contract_duplicates.is_empty());

    let trusted_root = function(152);
    let trusted_facts = root_duplicate_contract_artifact(trusted_root);
    let trusted_legacy = legacy_root_duplicate_contract_artifact(trusted_root);
    let trusted_request = root(trusted_root);
    let mut trusted_config = SniffTestConfig::default();
    trusted_config.panics.trusted_panic_boundary_namespaces =
        PathPatterns::new(vec![String::from("fixture::root")]).unwrap();
    let trusted = super::evaluate_typed_panic_call_roots(
        TypedPanicLocalArtifact::in_memory(&trusted_facts, LOCAL_CRATE),
        &[],
        Vec::new(),
        &[],
        std::slice::from_ref(&trusted_request),
        &trusted_config,
    )
    .expect("contract-before-trusted evaluation succeeds");
    assert_eq!(trusted.root_contracts[0].issues.len(), 1);
    assert_root_contract_finding_parity(
        &trusted.root_contracts[0],
        &trusted_legacy,
        &trusted_request,
        &trusted_config,
    );

    for (root_function, requirements) in [
        (function(153), Vec::new()),
        (function(154), vec![("Ready", "the value is ready", 60, 65)]),
    ] {
        let facts = root_contract_artifact(
            root_function,
            root_function,
            FunctionBodyProvenance::DefiningArtifact,
            Some(requirements.clone()),
        );
        let legacy = legacy_root_contract_artifact(root_function, Some(requirements));
        let request = root(root_function);
        let batch = super::evaluate_typed_panic_call_roots(
            TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
            &[],
            Vec::new(),
            &[],
            std::slice::from_ref(&request),
            &SniffTestConfig::default(),
        )
        .expect("unique or empty root-contract evaluation succeeds");
        let report = &batch.root_contracts[0];
        assert_eq!(report.selected_function, Some(root_function));
        assert!(report.issues.is_empty());
        assert!(batch.roots[0].issues.is_empty());
        assert_root_contract_finding_parity(report, &legacy, &request, &SniffTestConfig::default());
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the hostile matrix keeps every independent root-contract issue join visible"
)]
fn root_contract_projection_rejects_non_bijective_or_altered_issue_rows() {
    let root_function = function(155);
    let facts = root_duplicate_contract_artifact(root_function);
    let request = root(root_function);
    let (call, _, fixture) = evaluate_typed_panic_call_with_projection_fixture(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        [],
        &[],
        &request,
        &SniffTestConfig::default(),
    )
    .expect("root-contract hostile fixture evaluates");
    let [baseline] = fixture.root_contract_duplicates.as_slice() else {
        panic!("the hostile fixture has one canonical root-contract issue");
    };
    let boundary = super::root_contract_boundary(&fixture.inputs)
        .unwrap()
        .expect("the hostile fixture retains a root boundary");

    let mut cases = Vec::new();
    cases.push(("missing", Vec::new()));

    let mut duplicate = fixture.root_contract_duplicates.clone();
    duplicate.push(baseline.clone());
    cases.push(("duplicate", duplicate));

    let mut orphan = fixture.root_contract_duplicates.clone();
    orphan[0].data =
        crate::analysis::facts::panic::DuplicatePanicRootRequirementIssue::new("other", vec![0, 1]);
    cases.push(("orphan payload", orphan));

    let mut altered_ordinals = fixture.root_contract_duplicates.clone();
    altered_ordinals[0].data =
        crate::analysis::facts::panic::DuplicatePanicRootRequirementIssue::new(
            baseline.data.normalized_name(),
            vec![1, 0],
        );
    cases.push(("altered ordinals", altered_ordinals));

    let mut producer = fixture.root_contract_duplicates.clone();
    producer[0].producer = PassId::new("hostile.root-contract-producer").unwrap();
    cases.push(("producer", producer));

    let mut foreign_root = fixture.root_contract_duplicates.clone();
    foreign_root[0].context.root.domain = DomainId::new("hostile.panic").unwrap();
    cases.push(("root", foreign_root));

    let mut source = fixture.root_contract_duplicates.clone();
    source[0].context.source = None;
    cases.push(("source", source));

    let mut endpoint = fixture.root_contract_duplicates.clone();
    endpoint[0].context.endpoint = Some(boundary.callable().erase());
    cases.push(("endpoint", endpoint));

    let mut trace = fixture.root_contract_duplicates.clone();
    trace[0].context.trace = Some(crate::analysis::facts::evaluation::RelationTrace::new(
        call.root.entity.clone(),
        boundary.callable().erase(),
        Vec::new(),
    ));
    cases.push(("trace", trace));

    for (name, rows) in cases {
        let error = super::project_root_contract_report(
            &fixture.inputs,
            call.presentation_range.clone(),
            &request,
            &call.root,
            rows,
        )
        .expect_err("altered root-contract rows must reject the complete root report");
        assert!(
            error.to_string().contains("root-contract issue"),
            "{name}: {error}"
        );
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one adapter matrix proves whole-batch rejection before any source resolution"
)]
fn root_contract_adapter_preflights_the_entire_batch_before_source_resolution() {
    let first_function = function(144);
    let facts = root_duplicate_contract_artifact(first_function);
    let first_request = root(first_function);
    let batch = super::evaluate_typed_panic_call_roots(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        &[],
        Vec::new(),
        &[],
        std::slice::from_ref(&first_request),
        &SniffTestConfig::default(),
    )
    .expect("root-contract adapter fixture evaluates");
    let first = batch
        .root_contracts
        .into_iter()
        .next()
        .expect("the fixture retains its root-contract report");
    assert_eq!(first.issues.len(), 1);

    let second_request = InterpretationRoot {
        function: function(145),
        path: String::from("fixture::second_root"),
        kind: ReportRootKind::Concrete,
    };
    let mut second = first.clone();
    second.function = second_request.function;
    second.path.clone_from(&second_request.path);
    second.kind = second_request.kind;
    second.selected_function = Some(second.function);
    second.selected_path = Some(second.path.clone());
    for issue in &mut second.issues {
        issue.function = second.function;
        issue.function_path.clone_from(&second.path);
    }
    let roots = [first_request, second_request];

    let wrong_count_sources = CountingSources::default();
    let wrong_count = adapt_typed_panic_root_contract_reports(
        &wrong_count_sources,
        vec![first.clone()],
        &roots,
        false,
    )
    .expect_err("a missing root report must reject the complete root-contract batch");
    assert!(
        wrong_count
            .to_string()
            .contains("root-contract report batch")
    );
    assert_eq!(wrong_count_sources.calls.get(), 0);

    let reordered_sources = CountingSources::default();
    let reordered = adapt_typed_panic_root_contract_reports(
        &reordered_sources,
        vec![second.clone(), first.clone()],
        &roots,
        false,
    )
    .expect_err("reordered root reports must reject the complete root-contract batch");
    assert!(reordered.to_string().contains("root-contract root report"));
    assert_eq!(reordered_sources.calls.get(), 0);

    for (name, cross_root) in [("cross-root", true), ("selected identity", false)] {
        let mut hostile = second.clone();
        let issue = hostile
            .issues
            .last_mut()
            .expect("the late report retains one normal issue");
        if cross_root {
            issue.root.domain = DomainId::new("hostile.panic").unwrap();
        } else {
            issue.function_path = String::from("hostile::other_root");
        }
        let late_sources = CountingSources::default();
        let late = adapt_typed_panic_root_contract_reports(
            &late_sources,
            vec![first.clone(), hostile],
            &roots,
            true,
        )
        .expect_err("a late malformed issue must reject the whole root-contract batch");
        assert!(
            late.to_string().contains("root-contract issue report"),
            "{name}: {late}"
        );
        assert_eq!(late_sources.calls.get(), 0, "{name}");
    }

    let mut unrelated = second.clone();
    let unrelated_function = function(159);
    unrelated.selected_function = Some(unrelated_function);
    unrelated.selected_path = Some(String::from("hostile::unrelated"));
    for issue in &mut unrelated.issues {
        issue.function = unrelated_function;
        issue.function_path = String::from("hostile::unrelated");
    }
    let unrelated_sources = CountingSources::default();
    let unrelated_error = adapt_typed_panic_root_contract_reports(
        &unrelated_sources,
        vec![first.clone(), unrelated],
        &roots,
        true,
    )
    .expect_err("a self-consistent unrelated selected body must reject the complete batch");
    assert!(
        unrelated_error
            .to_string()
            .contains("root-contract root report")
    );
    assert_eq!(unrelated_sources.calls.get(), 0);

    let mut wrong_domain = second.clone();
    wrong_domain.root.domain = DomainId::new("hostile.panic").unwrap();
    for issue in &mut wrong_domain.issues {
        issue.root.clone_from(&wrong_domain.root);
    }
    let wrong_domain_sources = CountingSources::default();
    let wrong_domain_error = adapt_typed_panic_root_contract_reports(
        &wrong_domain_sources,
        vec![first.clone(), wrong_domain],
        &roots,
        true,
    )
    .expect_err("a coordinated foreign-domain root must reject the complete batch");
    assert!(
        wrong_domain_error
            .to_string()
            .contains("root-contract root report")
    );
    assert_eq!(wrong_domain_sources.calls.get(), 0);

    let mut wrong_schema = second.clone();
    let scope = wrong_schema.root.entity.scope().clone();
    let row = wrong_schema.root.entity.entity().row;
    wrong_schema.root.entity = ScopedEntityRef::new(
        scope,
        EntityRef {
            schema: SchemaId::new(CallOccurrenceEntity::ID).unwrap(),
            row,
        },
    );
    for issue in &mut wrong_schema.issues {
        issue.root.clone_from(&wrong_schema.root);
    }
    let wrong_schema_sources = CountingSources::default();
    let wrong_schema_error = adapt_typed_panic_root_contract_reports(
        &wrong_schema_sources,
        vec![first.clone(), wrong_schema],
        &roots,
        true,
    )
    .expect_err("a coordinated non-function root must reject the complete batch");
    assert!(
        wrong_schema_error
            .to_string()
            .contains("root-contract root report")
    );
    assert_eq!(wrong_schema_sources.calls.get(), 0);

    let mut reversed_requirements = second;
    reversed_requirements.issues[0].requirements.reverse();
    let reversed_sources = CountingSources::default();
    let reversed_error = adapt_typed_panic_root_contract_reports(
        &reversed_sources,
        vec![first, reversed_requirements],
        &roots,
        true,
    )
    .expect_err("reordered declaration members must reject the complete batch");
    assert!(
        reversed_error
            .to_string()
            .contains("root-contract issue report")
    );
    assert_eq!(reversed_sources.calls.get(), 0);
}
