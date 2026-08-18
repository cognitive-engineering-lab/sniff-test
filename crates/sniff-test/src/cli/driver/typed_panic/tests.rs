use reachability::MirBodyLocation;
use rustc_span::{BytePos, Span};

use super::*;
use crate::analysis::cache::{ArtifactInfo, CACHE_FORMAT_VERSION};
use crate::analysis::collected::{
    CollectedArtifact, CollectedArtifactInput, CollectedCallOccurrence, CollectedCallSite,
    CollectedCallTarget, CollectedEffectSite, CollectedEffectSourceAnchor, CollectedFunctionBody,
    CollectedMirAssert, CollectedProgram,
};
use crate::analysis::facts::collection::collect_artifact_facts;
use crate::analysis::facts::panic::CompilerAssertSemanticNodeRole;
use crate::analysis::facts::panic::model::MirAssertKind;
use crate::analysis::facts::program::topology::{
    CallAttributionRole, CallKind, CallOccurrenceEntity, CallOccurrenceKey, CallSiteEntity,
    CallSiteKey, CallTargetRole, CallableEntity, SafetyEffectGroupEntity, SafetyEffectGroupKey,
};
use crate::analysis::facts::program::{
    EffectSiteEntity, EffectSiteKey, EffectSourceAnchorRole, FunctionBodyProvenance,
    FunctionEntity, FunctionKey, SourceAnchorEntity, SourceAnchorKey, SourceFileEntity,
};
use crate::analysis::ir::{ArtifactAnalysisIr, StableInstanceHash};
use crate::analysis::workspace_closure::VerifiedWorkspaceClosureError;
use crate::cli::driver::interpretation::{FindingSources, adapt_typed_panic_reports};
use crate::cli::findings::{DiagnosticMessage, FindingKind};
use crate::namespace::StableDefPathHash;

const LOCAL_CRATE: u64 = 1;

fn definition(stable_crate_id: u64, local: u64) -> StableDefPathHash {
    serde_json::from_str(&format!("\"{stable_crate_id:016x}{local:016x}\""))
        .expect("valid stable definition hash")
}

fn function(local: u64) -> FunctionId {
    FunctionId::generic(definition(LOCAL_CRATE, local))
}

fn instance(local: u64) -> StableInstanceHash {
    serde_json::from_str(&format!("\"{local:032x}\"")).expect("valid stable instance hash")
}

fn key(function: FunctionId) -> FunctionKey {
    FunctionKey::new(function.def_path_hash, function.instance_hash)
}

fn root(function: FunctionId, path: &str) -> InterpretationRoot {
    InterpretationRoot {
        function,
        path: path.to_owned(),
        kind: ReportRootKind::Generic,
    }
}

fn callable(function: FunctionKey, path: &str) -> CallableEntity {
    CallableEntity::new(
        function,
        path,
        false,
        true,
        true,
        false,
        vec![path.to_owned()],
    )
}

fn assertion_site(function: FunctionKey, ordinal: usize) -> EffectSiteKey {
    EffectSiteKey::from_mir(
        function,
        MirBodyLocation {
            basic_block: ordinal,
            statement_index: 0,
        },
    )
    .expect("fixture MIR coordinate fits the permanent key")
}

fn permanent_artifact(
    functions: &[(FunctionId, &str, bool)],
    source: Option<(FunctionId, SourceAnchorKey, SourceAnchorKey)>,
) -> ArtifactFactIr {
    permanent_artifact_with_references(functions, &[], source)
}

fn permanent_artifact_with_references(
    functions: &[(FunctionId, &str, bool)],
    references: &[(FunctionId, &str)],
    source: Option<(FunctionId, SourceAnchorKey, SourceAnchorKey)>,
) -> ArtifactFactIr {
    let mut callables = Vec::new();
    let mut bodies = Vec::new();
    let mut assertions = Vec::new();

    for (ordinal, &(function, path, has_assertion)) in functions.iter().enumerate() {
        let function_key = key(function);
        callables.push(callable(function_key, path));
        let (body_anchor, effect_anchors) = source
            .as_ref()
            .filter(|(source_function, _, _)| *source_function == function)
            .map_or((None, Vec::new()), |(_, body_anchor, effect_anchor)| {
                (
                    Some(body_anchor.clone()),
                    vec![CollectedEffectSourceAnchor::new(
                        EffectSourceAnchorRole::Presentation,
                        effect_anchor.clone(),
                    )],
                )
            });
        let effect_sites = has_assertion
            .then(|| {
                let site = assertion_site(function_key, ordinal);
                assertions.push(CollectedMirAssert::new(site, MirAssertKind::BoundsCheck));
                CollectedEffectSite::new(EffectSiteEntity::new(site), effect_anchors, Vec::new())
            })
            .into_iter()
            .collect();
        bodies.push(CollectedFunctionBody::new(
            FunctionEntity::new(function_key, path, FunctionBodyProvenance::DefiningArtifact),
            body_anchor,
            Vec::new(),
            Vec::new(),
            effect_sites,
        ));
    }
    callables.extend(
        references
            .iter()
            .map(|&(function, path)| callable(key(function), path)),
    );

    let (files, anchors) = source.map_or((Vec::new(), Vec::new()), |(_, body, effect)| {
        let file = body.file().to_owned();
        assert_eq!(file, effect.file());
        (
            vec![SourceFileEntity::new(
                file,
                "src/lib.rs",
                "sha256:typed-panic-permanent-fixture",
                256,
            )],
            vec![
                SourceAnchorEntity::new(body),
                SourceAnchorEntity::new(effect),
            ],
        )
    });
    let program = CollectedProgram::try_new(files, anchors, callables, bodies)
        .expect("valid permanent program fixture");
    let artifact = CollectedArtifact::try_new(CollectedArtifactInput {
        program,
        unsafe_operations: Vec::new(),
        panic_contracts: Vec::new(),
        safety_contracts: Vec::new(),
        mir_asserts: assertions,
        marker_occurrences: Vec::new(),
    })
    .expect("valid permanent compiler-assert fixture");
    collect_artifact_facts(&artifact).expect("permanent fact collection succeeds")
}

fn permanent_call_artifact(root: FunctionId, asserted: FunctionId) -> ArtifactFactIr {
    let root_key = key(root);
    let asserted_key = key(asserted);
    let call_site = CallSiteKey::new(root_key, 0);
    let occurrence = CallOccurrenceKey::new(root_key, 0);
    let group = SafetyEffectGroupKey::new(root_key, 0);
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
            asserted_key,
        )],
        Vec::new(),
        vec![group],
        Vec::new(),
        Vec::new(),
    );
    let assertion = assertion_site(asserted_key, 0);
    let program = CollectedProgram::try_new(
        Vec::new(),
        Vec::new(),
        vec![
            callable(root_key, "fixture::root"),
            callable(asserted_key, "fixture::asserted"),
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
                    vec![call],
                )],
                vec![SafetyEffectGroupEntity::new(group)],
                Vec::new(),
            ),
            CollectedFunctionBody::new(
                FunctionEntity::new(
                    asserted_key,
                    "fixture::asserted",
                    FunctionBodyProvenance::DefiningArtifact,
                ),
                None,
                Vec::new(),
                Vec::new(),
                vec![CollectedEffectSite::new(
                    EffectSiteEntity::new(assertion),
                    Vec::new(),
                    Vec::new(),
                )],
            ),
        ],
    )
    .expect("valid permanent direct-call fixture");
    let artifact = CollectedArtifact::try_new(CollectedArtifactInput {
        program,
        unsafe_operations: Vec::new(),
        panic_contracts: Vec::new(),
        safety_contracts: Vec::new(),
        mir_asserts: vec![CollectedMirAssert::new(
            assertion,
            MirAssertKind::BoundsCheck,
        )],
        marker_occurrences: Vec::new(),
    })
    .expect("valid permanent direct-call artifact");
    collect_artifact_facts(&artifact).expect("permanent direct-call collection succeeds")
}

fn dependency_cache(
    id: RustcArtifactId,
    dependencies: Vec<RustcArtifactId>,
    facts: ArtifactFactIr,
) -> ArtifactAnalysisCache {
    ArtifactAnalysisCache {
        format_version: CACHE_FORMAT_VERSION,
        tool_version: String::from("test"),
        rustc_version: String::from("test"),
        artifact: ArtifactInfo {
            id,
            crate_name: String::from("fixture_dependency"),
        },
        dependencies,
        legacy_ir: ArtifactAnalysisIr::new(Vec::new(), Vec::new())
            .expect("empty legacy compatibility payload is valid"),
        facts,
    }
}

#[derive(Default)]
struct TypedCatalogSources {
    source_files: Vec<SourceFileIr>,
}

impl FindingSources for TypedCatalogSources {
    fn function_span(&self, _function: FunctionId) -> Option<Span> {
        None
    }

    fn resolve(&self, range: Option<&SourceRangeIr>) -> (Option<Span>, Option<String>) {
        let Some(range) = range else {
            return (None, None);
        };
        if self.source_file(range).is_none() {
            return (
                None,
                Some(format!(
                    "source file identity `{}` is absent from the composed artifact graph",
                    range.file.as_str()
                )),
            );
        }
        let start = u32::try_from(range.byte_start).expect("test source start fits u32");
        let end = u32::try_from(range.byte_end).expect("test source end fits u32");
        (
            Some(Span::with_root_ctxt(BytePos(start), BytePos(end))),
            None,
        )
    }

    fn source_file<'a>(&'a self, range: &SourceRangeIr) -> Option<&'a SourceFileIr> {
        self.source_files
            .binary_search_by(|source| source.id.cmp(&range.file))
            .ok()
            .map(|index| &self.source_files[index])
    }

    fn render_span(&self, span: Span) -> String {
        format!("bytes {}..{}", span.lo().0, span.hi().0)
    }
}

#[test]
fn permanent_local_assertion_evaluates_without_legacy_witnesses() {
    let function = function(1);
    let facts = permanent_artifact(&[(function, "fixture::root", true)], None);
    let report = evaluate_with_dependencies(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        [],
        &[],
        &root(function, "fixture::root"),
        &SniffTestConfig::default(),
    )
    .expect("permanent compiler-assert evaluation succeeds");

    assert_eq!(report.function, function);
    assert_eq!(report.issues.len(), 1);
    let issue = &report.issues[0];
    assert_eq!(issue.issue.data.witness_order(), 0);
    assert_eq!(issue.compiler_assert_kind, CompilerAssertKind::BoundsCheck);
    assert_eq!(issue.trace.witness_order(), 0);
    assert_eq!(issue.trace.steps().len(), 1);
    let terminal = &issue.trace.steps()[0];
    assert_eq!(terminal.position(), 0);
    assert_eq!(
        terminal.caller_role(),
        CompilerAssertSemanticNodeRole::Function
    );
    assert_eq!(
        terminal.target_role(),
        CompilerAssertSemanticNodeRole::CompilerAssert(MirAssertKind::BoundsCheck)
    );
    assert_eq!(
        terminal.edge(),
        CompilerAssertSemanticEdge::Assert(MirAssertKind::BoundsCheck)
    );
}

#[test]
fn each_root_uses_a_fresh_evaluation_database() {
    let asserted = function(1);
    let empty = function(2);
    let facts = permanent_artifact(
        &[
            (asserted, "fixture::asserted", true),
            (empty, "fixture::empty", false),
        ],
        None,
    );
    let roots = [
        root(asserted, "fixture::asserted"),
        root(empty, "fixture::empty"),
    ];
    let reports = evaluate_roots_with_dependencies(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        &[],
        Vec::new(),
        &[],
        &roots,
        &SniffTestConfig::default(),
    )
    .expect("both permanent roots evaluate atomically")
    .roots;

    assert_eq!(reports.len(), 2);
    assert_eq!(reports[0].issues.len(), 1);
    assert!(reports[1].issues.is_empty());
}

#[test]
fn exact_source_key_projects_file_identity_and_byte_bounds() {
    let function = function(1);
    let body = SourceAnchorKey::new("fixture-file", 5, 15);
    let effect = SourceAnchorKey::new("fixture-file", 40, 47);
    let facts = permanent_artifact(
        &[(function, "fixture::root", true)],
        Some((function, body.clone(), effect.clone())),
    );
    let report = evaluate_with_dependencies(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        [],
        &[],
        &root(function, "fixture::root"),
        &SniffTestConfig::default(),
    )
    .expect("permanent source projection succeeds");

    assert_eq!(report.presentation_range, Some(source_range(&body)));
    assert_eq!(
        report.issues[0].presentation_range,
        Some(source_range(&effect))
    );
    assert_eq!(
        report.issues[0].trace.steps()[0].source_key(),
        Some(&effect)
    );
}

#[test]
fn semantic_edges_keep_report_v13_labels_and_ordering() {
    assert_eq!(
        semantic_edge_label(CompilerAssertSemanticEdge::Call(CallKind::DirectCall)),
        "direct-call"
    );
    assert_eq!(
        semantic_edge_order(CompilerAssertSemanticEdge::Call(CallKind::DirectCall)),
        0
    );
    assert_eq!(
        semantic_edge_label(CompilerAssertSemanticEdge::MacroExpansion),
        "macro-expansion"
    );
    assert_eq!(
        semantic_edge_order(CompilerAssertSemanticEdge::Assert(
            MirAssertKind::BoundsCheck
        )),
        11
    );
}

#[test]
fn dependency_manifests_and_runtime_inventory_complete_the_typed_closure() {
    let root_function = function(10);
    let middle_function = FunctionId::generic(definition(2, 20));
    let leaf_function = FunctionId::generic(definition(3, 30));
    let runtime_function = FunctionId::generic(definition(4, 40));
    let root_facts = permanent_artifact_with_references(
        &[(root_function, "fixture::root", false)],
        &[(middle_function, "middle::entry")],
        None,
    );
    let middle_facts = permanent_artifact_with_references(
        &[(middle_function, "middle::entry", false)],
        &[(leaf_function, "leaf::entry")],
        None,
    );
    let leaf_facts = permanent_artifact_with_references(
        &[(leaf_function, "leaf::entry", false)],
        &[(runtime_function, "runtime::entry")],
        None,
    );
    let middle_id = RustcArtifactId::new(2, "22222222222222222222222222222222");
    let leaf_id = RustcArtifactId::new(3, "33333333333333333333333333333333");
    let runtime_id = RustcArtifactId::new(4, "44444444444444444444444444444444");
    let missing_leaf_manifest =
        dependency_cache(middle_id.clone(), Vec::new(), middle_facts.clone());
    let middle = dependency_cache(middle_id.clone(), vec![leaf_id.clone()], middle_facts);
    let leaf = dependency_cache(leaf_id, Vec::new(), leaf_facts);
    let roots = [root(root_function, "fixture::root")];

    let error = evaluate_roots_with_dependencies(
        TypedPanicLocalArtifact::in_memory(&root_facts, LOCAL_CRATE),
        &[&missing_leaf_manifest, &leaf],
        vec![middle_id.clone()],
        std::slice::from_ref(&runtime_id),
        &roots,
        &SniffTestConfig::default(),
    )
    .expect_err("a nested dependency must be declared by its owning manifest");
    assert!(matches!(
        error,
        TypedPanicEvaluationError::Closure(source)
            if matches!(
                source.as_ref(),
                VerifiedWorkspaceClosureError::UnreachableManagedGenerations { .. }
            )
    ));

    let error = evaluate_roots_with_dependencies(
        TypedPanicLocalArtifact::in_memory(&root_facts, LOCAL_CRATE),
        &[&middle, &leaf],
        vec![middle_id.clone()],
        &[],
        &roots,
        &SniffTestConfig::default(),
    )
    .expect_err("a typed unmanaged reference requires the active runtime identity");
    assert!(matches!(
        error,
        TypedPanicEvaluationError::Closure(source)
            if matches!(
                source.as_ref(),
                VerifiedWorkspaceClosureError::RuntimeArtifactUnavailable {
                    stable_crate_id: 4,
                    ..
                }
            )
    ));

    let batch = evaluate_roots_with_dependencies(
        TypedPanicLocalArtifact::in_memory(&root_facts, LOCAL_CRATE),
        &[&middle, &leaf],
        vec![middle_id],
        &[runtime_id],
        &roots,
        &SniffTestConfig::default(),
    )
    .expect("the exact nested manifests and runtime inventory complete the closure");
    assert_eq!(batch.roots.len(), 1);
    assert!(batch.roots[0].issues.is_empty());
}

#[test]
fn exact_root_falls_back_to_the_generic_body_in_the_same_scope() {
    let generic = function(50);
    let exact = FunctionId::exact(generic.def_path_hash, instance(51));
    let facts = permanent_artifact(&[(generic, "fixture::generic", true)], None);

    let report = evaluate_with_dependencies(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        [],
        &[],
        &InterpretationRoot {
            function: exact,
            path: String::from("fixture::generic::<Local>"),
            kind: ReportRootKind::Concrete,
        },
        &SniffTestConfig::default(),
    )
    .expect("an exact request resolves the same-scope generic defining body");

    let expected_scope = ArtifactScopeId::for_in_memory(LOCAL_CRATE, 0);
    assert_eq!(report.function, exact);
    assert_eq!(report.kind, ReportRootKind::Concrete);
    assert_eq!(report.root.entity.scope(), &expected_scope);
    assert_eq!(report.issues.len(), 1);
    assert_eq!(
        report.issues[0].issue.data.endpoint().scope(),
        &expected_scope
    );
    assert_eq!(
        report.issues[0].trace.steps()[0].caller_display_path(),
        Some("fixture::generic")
    );
}

#[test]
fn a_late_missing_root_rejects_the_whole_typed_batch() {
    let present = function(60);
    let missing = function(61);
    let facts = permanent_artifact(&[(present, "fixture::present", true)], None);
    let roots = [
        root(present, "fixture::present"),
        root(missing, "fixture::missing"),
    ];

    let error = evaluate_roots_with_dependencies(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        &[],
        Vec::new(),
        &[],
        &roots,
        &SniffTestConfig::default(),
    )
    .expect_err("failure while preparing the later root returns no report batch");

    assert!(matches!(error, TypedPanicEvaluationError::Input(_)));
}

#[test]
fn typed_source_catalog_alone_resolves_report_v13_spans() {
    rustc_span::create_default_session_globals_then(|| {
        let function = function(70);
        let body = SourceAnchorKey::new("fixture-file", 5, 15);
        let effect = SourceAnchorKey::new("fixture-file", 40, 47);
        let facts = permanent_artifact(
            &[(function, "fixture::root", true)],
            Some((function, body, effect)),
        );
        let roots = [root(function, "fixture::root")];
        let batch = evaluate_roots_with_dependencies(
            TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
            &[],
            Vec::new(),
            &[],
            &roots,
            &SniffTestConfig::default(),
        )
        .expect("typed source facts survive permanent evaluation");
        assert_eq!(batch.source_files.len(), 1);
        assert_eq!(batch.source_files[0].filename, "src/lib.rs");
        let sources = TypedCatalogSources {
            source_files: batch.source_files,
        };

        let findings = adapt_typed_panic_reports(&sources, batch.roots, &roots, false)
            .expect("the report adapter resolves spans from the typed-only catalog");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].root_span.as_deref(), Some("bytes 5..15"));
        assert_eq!(findings[0].span.as_deref(), Some("bytes 40..47"));
        assert_eq!(findings[0].diagnostic.span.map(Span::lo), Some(BytePos(5)));
        assert_eq!(
            findings[0].trace,
            ["bytes 40..47: fixture::root --assert-> compiler assert index out of bounds"]
        );
    });
}

#[test]
fn compact_and_full_report_v13_modes_keep_identical_public_semantics() {
    let root_function = function(80);
    let asserted_definition = function(81);
    let asserted = FunctionId::exact(asserted_definition.def_path_hash, instance(82));
    let facts = permanent_call_artifact(root_function, asserted);
    let roots = [root(root_function, "fixture::root")];
    let report = evaluate_with_dependencies(
        TypedPanicLocalArtifact::in_memory(&facts, LOCAL_CRATE),
        [],
        &[],
        &roots[0],
        &SniffTestConfig::default(),
    )
    .expect("the permanent call trace evaluates");
    let sources = TypedCatalogSources::default();

    let compact = adapt_typed_panic_reports(&sources, vec![report.clone()], &roots, false)
        .expect("compact report-v13 adaptation succeeds");
    let full = adapt_typed_panic_reports(&sources, vec![report], &roots, true)
        .expect("full report-v13 adaptation succeeds");

    assert_eq!(
        serde_json::to_value(&compact).expect("compact report serializes"),
        serde_json::to_value(&full).expect("full report serializes")
    );
    assert_eq!(
        compact[0].kind,
        FindingKind::CompilerAssert {
            compiler_assert_kind: CompilerAssertKind::BoundsCheck,
        }
    );
    assert_eq!(
        compact[0].trace,
        [
            "fixture::root --direct-call-> fixture::asserted",
            "fixture::asserted --assert-> compiler assert index out of bounds",
        ]
    );
    assert!(compact[0].diagnostic.messages.iter().any(|message| {
        matches!(
            message,
            DiagnosticMessage::Note(note)
                if note == "reachable from `fixture::root` to `compiler assert index out of bounds`"
        )
    }));
    assert!(compact[0].diagnostic.messages.iter().any(|message| {
        matches!(
            message,
            DiagnosticMessage::Note(note) if note.contains("show-full-stack-trace = true")
        )
    }));
    assert!(full[0].diagnostic.messages.iter().any(|message| {
        matches!(
            message,
            DiagnosticMessage::Note(note)
                if note == "reachable step 0: fixture::asserted --assert-> compiler assert index out of bounds"
        )
    }));
    assert!(!full[0].diagnostic.messages.iter().any(|message| {
        matches!(
            message,
            DiagnosticMessage::Note(note) if note.contains("show-full-stack-trace = true")
        )
    }));
}
