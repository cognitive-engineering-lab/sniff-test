//! Validated evaluation ingress for permanent compiler-assert root inputs.
//!
//! Root traversal prepares immutable, workspace-branded inputs. This rule is
//! the only boundary that turns those inputs into evaluation rows. It checks
//! the complete batch before emitting anything, so a malformed later witness
//! cannot leave a valid prefix in the rule delta.

use std::collections::{BTreeMap, BTreeSet};

use super::compiler_assert_inputs::{
    CompilerAssertRootInputs, PanicRootInputs, ReachableCompilerAssertInput,
};
use super::compiler_assert_trace::{
    CompilerAssertSemanticEdge, CompilerAssertSemanticNodeRole, CompilerAssertSemanticTrace,
    CompilerAssertTraceProjector,
};
use super::model::{MirAssertFact, PanicEvidenceOrdering, ReachableMirAssert};
use super::render::coarse_public_assert_kind;
use super::rules::panic_domain;
use crate::analysis::facts::encoded::TableKind;
use crate::analysis::facts::evaluation::{
    EvaluationCx, EvaluationInput, EvaluationOutput, EvaluationRule, RuleDescriptor, RuleError,
};
use crate::analysis::facts::evidence::{
    EvidenceSemanticEdgeOrder, EvidenceSemanticOrder, EvidenceSemanticSourceOrder,
    EvidenceSemanticStepOrder,
};
use crate::analysis::facts::human::markers::MarkerClaimEntity;
use crate::analysis::facts::human::{EvidenceAttachment, EvidenceClaimSelector};
use crate::analysis::facts::pack::{AnalysisPack, AnalysisRegistry, PackRegistrationError};
use crate::analysis::facts::program::root_traversal::ResolvedEffectVisit;
use crate::analysis::facts::program::topology::CallKind;
use crate::analysis::facts::program::{EffectSiteEntity, FunctionEntity};
use crate::analysis::facts::schema::PassId;
use crate::analysis::facts::workspace::ScopedRowRef;

const EMIT_COMPILER_ASSERT_INPUTS_RULE: &str = "sniff-test.panic.emit-compiler-assert-inputs";

/// Installs the permanent compiler-assert evaluation ingress.
///
/// The permanent artifact schemas, [`super::rules::PanicPack`], and
/// [`crate::analysis::facts::human::HumanEvidencePack`] must be installed
/// before this pack so all three output schemas already have concrete types.
/// The scheduler subsequently orders this producer ahead of the panic rules
/// through their declared schema dependencies, independently of registration
/// order.
pub(crate) struct CompilerAssertInputPack;

impl AnalysisPack<CompilerAssertRootInputs> for CompilerAssertInputPack {
    fn register(
        &self,
        registry: &mut AnalysisRegistry<CompilerAssertRootInputs>,
    ) -> Result<(), PackRegistrationError> {
        registry.register_evaluation_rule(EmitCompilerAssertInputs)
    }
}

impl AnalysisPack<PanicRootInputs> for CompilerAssertInputPack {
    fn register(
        &self,
        registry: &mut AnalysisRegistry<PanicRootInputs>,
    ) -> Result<(), PackRegistrationError> {
        registry.register_evaluation_rule(EmitCompilerAssertInputs)
    }
}

struct EmitCompilerAssertInputs;

impl EvaluationRule<CompilerAssertRootInputs> for EmitCompilerAssertInputs {
    fn descriptor(&self) -> RuleDescriptor {
        compiler_assert_input_descriptor()
    }

    fn evaluate(
        &self,
        cx: &EvaluationCx<'_, CompilerAssertRootInputs>,
        input: &EvaluationInput<'_>,
        output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError> {
        emit_compiler_assert_inputs(cx.root(), cx.services(), input, output)
    }
}

impl EvaluationRule<PanicRootInputs> for EmitCompilerAssertInputs {
    fn descriptor(&self) -> RuleDescriptor {
        compiler_assert_input_descriptor()
    }

    fn evaluate(
        &self,
        cx: &EvaluationCx<'_, PanicRootInputs>,
        input: &EvaluationInput<'_>,
        output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError> {
        emit_compiler_assert_inputs(cx.root(), cx.services().compiler_asserts(), input, output)
    }
}

fn compiler_assert_input_descriptor() -> RuleDescriptor {
    RuleDescriptor::new(PassId::new(EMIT_COMPILER_ASSERT_INPUTS_RULE).unwrap())
        .read::<MirAssertFact>()
        .read::<EffectSiteEntity>()
        .read::<FunctionEntity>()
        .read::<MarkerClaimEntity>()
        .write_derived::<ReachableMirAssert>()
        .write_derived::<PanicEvidenceOrdering>()
        .write_derived::<EvidenceAttachment>()
}

fn emit_compiler_assert_inputs(
    root: &crate::analysis::facts::evaluation::EvaluationRoot,
    services: &CompilerAssertRootInputs,
    input: &EvaluationInput<'_>,
    output: &mut EvaluationOutput<'_>,
) -> Result<(), RuleError> {
    validate_context(root, services, input)?;
    if root.domain != panic_domain() {
        return Ok(());
    }

    let batch = validate_batch(services, input, output)?;
    for reachable in &batch.reachable {
        output.emit_derived(reachable)?;
    }
    for ordering in &batch.orderings {
        output.emit_derived(ordering)?;
    }
    for attachment in &batch.attachments {
        output.emit_derived(attachment)?;
    }
    Ok(())
}

fn validate_context(
    root: &crate::analysis::facts::evaluation::EvaluationRoot,
    services: &CompilerAssertRootInputs,
    input: &EvaluationInput<'_>,
) -> Result<(), RuleError> {
    if !input.has_workspace_identity(services.workspace_identity()) {
        return Err(RuleError::failed(
            "compiler-assert inputs belong to a replacement workspace fact view",
        ));
    }
    if services.root() != root {
        return Err(RuleError::failed(
            "compiler-assert inputs belong to a different evaluation root",
        ));
    }
    Ok(())
}

struct ValidatedBatch {
    reachable: Vec<ReachableMirAssert>,
    orderings: Vec<PanicEvidenceOrdering>,
    attachments: Vec<EvidenceAttachment>,
}

fn validate_batch(
    services: &CompilerAssertRootInputs,
    input: &EvaluationInput<'_>,
    output: &EvaluationOutput<'_>,
) -> Result<ValidatedBatch, RuleError> {
    let mut reachable = Vec::with_capacity(services.assertions().len());
    let mut orderings = Vec::with_capacity(services.assertions().len());
    let mut attachments = Vec::new();
    let mut visit_orders = BTreeSet::new();
    let mut visits_by_order = BTreeMap::new();
    for visit in services.traversal().effect_visits() {
        if visits_by_order.insert(visit.order(), visit).is_some() {
            return Err(RuleError::failed(format!(
                "resolved compiler-assert traversal repeats effect visit order {}",
                visit.order()
            )));
        }
    }
    for (index, assertion) in services.assertions().iter().enumerate() {
        let expected_order = u64::try_from(index)
            .map_err(|_| RuleError::failed("compiler-assert witness order exceeds u64"))?;
        if assertion.order() != expected_order {
            return Err(RuleError::failed(format!(
                "compiler-assert witness order {} is not dense at position {index}",
                assertion.order()
            )));
        }
        if !visit_orders.insert(assertion.visit_order()) {
            return Err(RuleError::failed(format!(
                "compiler-assert inputs repeat effect visit order {}",
                assertion.visit_order()
            )));
        }
        let visit = visits_by_order
            .get(&assertion.visit_order())
            .copied()
            .ok_or_else(|| invalid_assertion(assertion, "has no matching resolved effect visit"))?;
        validate_assertion(services.root(), assertion, visit, input, output)?;

        let endpoint = assertion.owner().erase();
        reachable.push(ReachableMirAssert::new(
            assertion.source().clone(),
            endpoint.clone(),
            assertion.trace().clone(),
            assertion.order(),
        ));
        attachments.extend(assertion.markers().iter().map(|marker| {
            EvidenceAttachment::new(
                marker.claim().clone(),
                assertion.source().clone(),
                endpoint.clone(),
                endpoint.clone(),
                assertion.trace().clone(),
                assertion.order(),
                assertion.requirements().to_vec(),
            )
        }));
    }

    let projector = CompilerAssertTraceProjector::prepare(services)
        .map_err(|error| RuleError::failed(error.to_string()))?;
    for assertion in services.assertions() {
        let endpoint = assertion.owner().erase();
        let projected = projector
            .project(assertion.order())
            .map_err(|error| RuleError::failed(error.to_string()))?;
        if projected.assertion() != assertion.source()
            || projected.endpoint().erase() != endpoint
            || projected.witness_order() != assertion.order()
        {
            return Err(invalid_assertion(
                assertion,
                "semantic ordering projection changed its witness identity",
            ));
        }
        let semantic_order = semantic_order_for_trace(&projected, assertion.visit_order())?;
        orderings.push(PanicEvidenceOrdering::new(
            assertion.source().clone(),
            endpoint,
            assertion.trace().target().clone(),
            assertion.trace().clone(),
            assertion.order(),
            semantic_order,
        ));
    }

    Ok(ValidatedBatch {
        reachable,
        orderings,
        attachments,
    })
}

pub(super) fn semantic_order_for_trace(
    trace: &CompilerAssertSemanticTrace,
    traversal_order: u64,
) -> Result<EvidenceSemanticOrder, RuleError> {
    let steps = trace
        .steps()
        .iter()
        .map(|step| {
            let caller = semantic_node_label(step.caller_role(), step.caller_display_path())?;
            let target = Some(semantic_node_label(
                step.target_role(),
                step.target_display_path(),
            )?);
            let kind = match step.edge() {
                CompilerAssertSemanticEdge::MacroExpansion => {
                    EvidenceSemanticEdgeOrder::Reachability(CallKind::MacroExpansion)
                }
                CompilerAssertSemanticEdge::Call(kind) => {
                    EvidenceSemanticEdgeOrder::Reachability(kind)
                }
                CompilerAssertSemanticEdge::Assert(_) => {
                    EvidenceSemanticEdgeOrder::Reachability(CallKind::Assert)
                }
            };
            let source = step.source_key().map(|source| {
                EvidenceSemanticSourceOrder::new(source.byte_start(), source.byte_end())
            });
            Ok(EvidenceSemanticStepOrder::new(caller, kind, target, source))
        })
        .collect::<Result<Vec<_>, RuleError>>()?;
    let order = EvidenceSemanticOrder::new(steps, traversal_order);
    order.validate().map_err(RuleError::failed)?;
    Ok(order)
}

fn semantic_node_label(
    role: CompilerAssertSemanticNodeRole,
    display_path: Option<&str>,
) -> Result<String, RuleError> {
    match role {
        CompilerAssertSemanticNodeRole::Function | CompilerAssertSemanticNodeRole::Callable => {
            display_path
                .map(String::from)
                .ok_or_else(|| RuleError::failed("semantic evidence path node has no display path"))
        }
        CompilerAssertSemanticNodeRole::Macro => display_path
            .map(|path| format!("macro {path}"))
            .ok_or_else(|| RuleError::failed("semantic macro path node has no display path")),
        CompilerAssertSemanticNodeRole::CompilerAssert(kind) => Ok(format!(
            "compiler assert {}",
            coarse_public_assert_kind(kind).human_description()
        )),
    }
}

fn validate_assertion(
    root: &crate::analysis::facts::evaluation::EvaluationRoot,
    assertion: &ReachableCompilerAssertInput,
    visit: &ResolvedEffectVisit,
    input: &EvaluationInput<'_>,
    output: &EvaluationOutput<'_>,
) -> Result<(), RuleError> {
    let source = assertion.source();
    let fact = input.artifact_fact_at::<MirAssertFact>(source)?;
    if fact.fact.data.kind() != assertion.kind() {
        return Err(invalid_assertion(
            assertion,
            "kind disagrees with its permanent MIR assertion fact",
        ));
    }
    if source.scope() != assertion.owner().scope()
        || fact.metadata.owner.as_ref() != Some(&assertion.owner().entity().erase())
    {
        return Err(invalid_assertion(
            assertion,
            "owner disagrees with its permanent MIR assertion fact",
        ));
    }
    if source.scope() != assertion.provenance().scope()
        || fact.metadata.provenance_root.as_ref() != Some(&assertion.provenance().entity().erase())
    {
        return Err(invalid_assertion(
            assertion,
            "provenance disagrees with its permanent MIR assertion fact",
        ));
    }

    let effect = input.artifact_entity_at::<EffectSiteEntity>(&assertion.owner().erase())?;
    let function = input.artifact_entity_at::<FunctionEntity>(&assertion.provenance().erase())?;
    if effect.site().function() != function.key() {
        return Err(invalid_assertion(
            assertion,
            "effect owner and function provenance disagree",
        ));
    }

    let requirements = fact
        .metadata
        .requirements
        .into_iter()
        .map(|requirement| ScopedRowRef::new(source.scope().clone(), requirement))
        .collect::<Vec<_>>();
    if requirements.is_empty() || requirements != assertion.requirements() {
        return Err(invalid_assertion(
            assertion,
            "requirements disagree with its permanent MIR assertion fact",
        ));
    }
    let mut unique_requirements = BTreeSet::new();
    for requirement in assertion.requirements() {
        if !unique_requirements.insert(requirement) {
            return Err(invalid_assertion(
                assertion,
                "requirements contain a duplicate row",
            ));
        }
        output.validate_row_reference(requirement, Some(TableKind::Requirement))?;
    }

    if visit.effect() != assertion.owner()
        || visit.data() != &effect
        || visit.source_anchors() != assertion.source_anchors()
        || visit.macro_frames() != assertion.macro_frames()
        || visit.trace() != assertion.trace()
    {
        return Err(invalid_assertion(
            assertion,
            "owner or route metadata disagrees with its resolved effect visit",
        ));
    }
    if assertion.trace().root() != &root.entity
        || assertion.trace().target() != &assertion.owner().erase()
    {
        return Err(invalid_assertion(
            assertion,
            "trace does not connect the active root to its effect owner",
        ));
    }
    output.validate_relation_trace(assertion.trace())?;

    validate_markers(assertion, visit.active_markers(), input, output)
}

fn validate_markers(
    assertion: &ReachableCompilerAssertInput,
    active: &[crate::analysis::facts::program::root_traversal::ResolvedMarkerClaim],
    input: &EvaluationInput<'_>,
    output: &EvaluationOutput<'_>,
) -> Result<(), RuleError> {
    let eligible = active
        .iter()
        .filter(|marker| {
            marker.data().key().domain() == &panic_domain()
                && marker.data().selector() == &EvidenceClaimSelector::Unnamed
                && !marker.data().rationale().trim().is_empty()
        })
        .collect::<Vec<_>>();
    if eligible.len() != assertion.markers().len() {
        return Err(invalid_assertion(
            assertion,
            "marker set disagrees with its resolved active marker state",
        ));
    }

    let mut claims = BTreeSet::new();
    for (marker, expected) in assertion.markers().iter().zip(eligible) {
        if marker.claim() != expected.claim()
            || marker.data() != expected.data()
            || marker.trace() != expected.trace()
        {
            return Err(invalid_assertion(
                assertion,
                "marker identity, data, or activation trace was altered",
            ));
        }
        if !claims.insert(marker.claim()) {
            return Err(invalid_assertion(
                assertion,
                "marker set repeats a permanent claim entity",
            ));
        }
        let persisted = input.artifact_entity_at::<MarkerClaimEntity>(&marker.claim().erase())?;
        if &persisted != marker.data()
            || persisted.key().domain() != &panic_domain()
            || persisted.selector() != &EvidenceClaimSelector::Unnamed
            || persisted.rationale().trim().is_empty()
        {
            return Err(invalid_assertion(
                assertion,
                "marker claim is not eligible permanent panic evidence",
            ));
        }
        if marker.trace().root() != assertion.trace().root()
            || marker.trace().target() != &marker.claim().erase()
        {
            return Err(invalid_assertion(
                assertion,
                "marker activation trace does not connect the active root to its claim",
            ));
        }
        output.validate_relation_trace(marker.trace())?;
    }
    Ok(())
}

fn invalid_assertion(assertion: &ReachableCompilerAssertInput, reason: &str) -> RuleError {
    RuleError::failed(format!(
        "compiler-assert witness {} {reason}",
        assertion.order()
    ))
}

#[cfg(test)]
mod tests {
    use super::super::compiler_assert_inputs::{
        CompilerAssertRootInputs, CompilerAssertRootRequest, PanicRootInputs,
        PreparedCompilerAssertRootBatch,
    };
    use super::{CompilerAssertInputPack, EMIT_COMPILER_ASSERT_INPUTS_RULE, semantic_node_label};
    use crate::analysis::cache::RustcArtifactId;
    use crate::analysis::facts::builder::{ArtifactDbBuilder, FactMeta};
    use crate::analysis::facts::collection::CollectedArtifactSchemaPack;
    use crate::analysis::facts::composition::{
        CompositionRelationBuilder, WorkspaceEvaluationView, WorkspaceRelationGraph,
    };
    use crate::analysis::facts::encoded::TableKind;
    use crate::analysis::facts::evaluation::{
        DomainId, EvaluationDb, EvaluationPipelineError, EvaluationRoot, RelationTrace,
    };
    use crate::analysis::facts::human::markers::{
        EffectSiteHasMarkerClaimCandidate, MarkerClaimEntity, MarkerClaimKey,
        MarkerOccurrenceEntity, MarkerOccurrenceHasClaim, MarkerOccurrenceHasSourceAnchor,
        MarkerOccurrenceKey,
    };
    use crate::analysis::facts::human::{
        EvidenceAttachment, EvidenceClaimSelector, HumanEvidencePack,
    };
    use crate::analysis::facts::pack::{AnalysisPack, AnalysisRegistry};
    use crate::analysis::facts::panic::compiler_assert_trace::CompilerAssertSemanticNodeRole;
    use crate::analysis::facts::panic::model::{
        InBoundsRequirement, MirAssertFact, MirAssertKind, PanicEvidenceOrdering,
        ReachableMirAssert,
    };
    use crate::analysis::facts::program::root_traversal::MarkerProbe;
    use crate::analysis::facts::program::topology::{
        CallAttributionRole, CallableEntity, FunctionDefinesCallable,
    };
    use crate::analysis::facts::program::{
        EffectSiteEntity, EffectSiteKey, FunctionBodyProvenance, FunctionEntity, FunctionKey,
        FunctionOwnsEffectSite, SourceAnchorEntity, SourceAnchorInFile, SourceAnchorKey,
        SourceFileEntity,
    };
    use crate::analysis::facts::schema::{PassId, RowSchema};
    use crate::analysis::facts::view::ArtifactDbView;
    use crate::analysis::facts::workspace::{ArtifactScopeId, WorkspaceFactView};
    use crate::analysis::workspace_closure::{
        ManagedArtifactGeneration, ManagedArtifactManifest, VerifiedWorkspaceClosure,
    };
    use crate::config::PanicConfig;
    use crate::contracts::ContractDocOverrides;
    use crate::namespace::StableDefPathHash;
    use reachability::MirBodyLocation;

    fn definition(local: u64) -> StableDefPathHash {
        serde_json::from_str(&format!("\"0000000000000001{local:016x}\"")).unwrap()
    }

    fn registry() -> AnalysisRegistry<CompilerAssertRootInputs> {
        let mut registry = AnalysisRegistry::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        registry.install(&HumanEvidencePack).unwrap();
        registry.register_derived::<ReachableMirAssert>().unwrap();
        registry
            .register_derived::<PanicEvidenceOrdering>()
            .unwrap();
        registry.install(&CompilerAssertInputPack).unwrap();
        registry
    }

    #[test]
    fn compiler_assert_ingress_supports_the_combined_panic_root_service() {
        fn assert_pack<P: AnalysisPack<PanicRootInputs>>(_pack: &P) {}

        assert_pack(&CompilerAssertInputPack);
    }

    fn declared_builder(
        registry: &AnalysisRegistry<CompilerAssertRootInputs>,
    ) -> ArtifactDbBuilder {
        let mut builder = ArtifactDbBuilder::new();
        for descriptor in registry.schemas().descriptors().filter(|descriptor| {
            !matches!(descriptor.kind(), TableKind::Derived | TableKind::Issue)
        }) {
            builder.declare_table(descriptor).unwrap();
        }
        builder
    }

    fn insert_root(
        builder: &mut ArtifactDbBuilder,
        root: FunctionKey,
    ) -> crate::analysis::facts::schema::EntityHandle<FunctionEntity> {
        let body = builder
            .insert_entity(&FunctionEntity::new(
                root,
                "crate::root",
                FunctionBodyProvenance::DefiningArtifact,
            ))
            .unwrap();
        let callable = builder
            .insert_entity(&CallableEntity::new(
                root,
                "crate::root",
                false,
                false,
                true,
                false,
                vec![String::from("crate::root")],
            ))
            .unwrap();
        builder
            .relate(&body, &callable, &FunctionDefinesCallable::new())
            .unwrap();
        body
    }

    fn insert_assertions(
        builder: &mut ArtifactDbBuilder,
        body: &crate::analysis::facts::schema::EntityHandle<FunctionEntity>,
        root: FunctionKey,
        count: usize,
    ) -> Vec<crate::analysis::facts::schema::EntityHandle<EffectSiteEntity>> {
        (0..count)
            .map(|index| {
                let effect = builder
                    .insert_entity(&EffectSiteEntity::new(
                        EffectSiteKey::from_mir(
                            root,
                            MirBodyLocation {
                                basic_block: index + 1,
                                statement_index: 0,
                            },
                        )
                        .unwrap(),
                    ))
                    .unwrap();
                builder
                    .relate(body, &effect, &FunctionOwnsEffectSite::new())
                    .unwrap();
                let requirement = builder
                    .insert_requirement(&InBoundsRequirement::new())
                    .unwrap();
                builder
                    .insert_fact(
                        &MirAssertFact::new(MirAssertKind::BoundsCheck),
                        FactMeta::new(PassId::new("test.compiler-assert-ingress").unwrap())
                            .with_owner(&effect)
                            .unwrap()
                            .with_provenance_root(body)
                            .unwrap()
                            .with_requirement(&requirement)
                            .unwrap(),
                    )
                    .unwrap();
                effect
            })
            .collect()
    }

    fn attach_marker(
        builder: &mut ArtifactDbBuilder,
        effect: &crate::analysis::facts::schema::EntityHandle<EffectSiteEntity>,
    ) {
        let file = builder
            .insert_entity(&SourceFileEntity::new(
                "marker-file",
                "src/lib.rs",
                "marker-content-hash",
                100,
            ))
            .unwrap();
        let anchor_key = SourceAnchorKey::new("marker-file", 0, 5);
        let anchor = builder
            .insert_entity(&SourceAnchorEntity::new(anchor_key.clone()))
            .unwrap();
        builder
            .relate(&anchor, &file, &SourceAnchorInFile::new())
            .unwrap();
        let occurrence_key = MarkerOccurrenceKey::new(anchor_key, None);
        let occurrence = builder
            .insert_entity(&MarkerOccurrenceEntity::new(occurrence_key.clone(), vec![]))
            .unwrap();
        builder
            .relate(
                &occurrence,
                &anchor,
                &MarkerOccurrenceHasSourceAnchor::new(),
            )
            .unwrap();
        let claim = builder
            .insert_entity(&MarkerClaimEntity::new(
                MarkerClaimKey::new(occurrence_key, super::panic_domain(), 0),
                EvidenceClaimSelector::Unnamed,
                "the index is known to be in bounds",
            ))
            .unwrap();
        builder
            .relate(&occurrence, &claim, &MarkerOccurrenceHasClaim::new())
            .unwrap();
        builder
            .relate(
                effect,
                &claim,
                &EffectSiteHasMarkerClaimCandidate::new(true, false),
            )
            .unwrap();
    }

    fn with_inputs(
        assertion_count: usize,
        with_marker: bool,
        test: impl FnOnce(
            &AnalysisRegistry<CompilerAssertRootInputs>,
            &crate::analysis::facts::encoded::ArtifactFactIr,
            &WorkspaceFactView<'_>,
            CompilerAssertRootInputs,
            WorkspaceRelationGraph,
        ),
    ) {
        let registry = registry();
        let root = FunctionKey::new(definition(1), None);
        let mut builder = declared_builder(&registry);
        let body = insert_root(&mut builder, root);
        let effects = insert_assertions(&mut builder, &body, root, assertion_count);
        if with_marker {
            attach_marker(&mut builder, &effects[0]);
        }
        let artifact = builder.finalize(registry.schemas()).unwrap();
        let scope = ArtifactScopeId::for_in_memory(1, 0);
        let workspace = WorkspaceFactView::compose([(
            scope,
            ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
        )])
        .unwrap();
        let closure = VerifiedWorkspaceClosure::open(
            &workspace,
            ManagedArtifactManifest::new(ManagedArtifactGeneration::in_memory(1, 0), vec![]),
            [],
            Vec::<RustcArtifactId>::new(),
        )
        .unwrap();
        let batch = PreparedCompilerAssertRootBatch::prepare(
            &workspace,
            &closure,
            &PanicConfig::default(),
            &ContractDocOverrides::default(),
            [CompilerAssertRootRequest::new(
                root,
                CallAttributionRole::CallSite,
                MarkerProbe::SourceCallsite,
                32,
            )],
        )
        .unwrap();
        let prepared = batch.into_roots().pop().unwrap();
        let mut composition_builder = CompositionRelationBuilder::new(
            prepared.root(),
            &workspace,
            registry.composition_relations(),
        )
        .unwrap();
        let emitted = prepared.emit(&mut composition_builder).unwrap();
        let composition = composition_builder.finalize().unwrap();
        let graph = WorkspaceRelationGraph::new(emitted.root(), &workspace, &composition).unwrap();
        let inputs = emitted
            .resolve(&workspace, &graph, registry.composition_relations())
            .unwrap();
        test(&registry, &artifact, &workspace, inputs, graph);
    }

    fn run_ingress(
        registry: &AnalysisRegistry<CompilerAssertRootInputs>,
        workspace: &WorkspaceFactView<'_>,
        inputs: &CompilerAssertRootInputs,
        graph: WorkspaceRelationGraph,
        evaluated: &mut EvaluationDb,
    ) -> Result<(), EvaluationPipelineError> {
        let root = inputs.root().clone();
        let evaluation = WorkspaceEvaluationView::from_graph(workspace, graph).unwrap();
        registry.run_workspace_evaluation(inputs, &root, &evaluation, evaluated)
    }

    #[test]
    fn emits_exact_reachable_assertions_and_marker_attachments() {
        with_inputs(2, true, |registry, _, workspace, inputs, graph| {
            let mut evaluated = EvaluationDb::new();
            run_ingress(registry, workspace, &inputs, graph, &mut evaluated).unwrap();
            let results = evaluated.finish().unwrap();
            let reachable = results
                .derived_rows::<ReachableMirAssert>(registry.schemas())
                .unwrap();
            let orderings = results
                .derived_rows::<PanicEvidenceOrdering>(registry.schemas())
                .unwrap();
            let attachments = results
                .derived_rows::<EvidenceAttachment>(registry.schemas())
                .unwrap();

            assert_eq!(reachable.len(), 2);
            assert_eq!(orderings.len(), reachable.len());
            assert_eq!(attachments.len(), 1);
            for ordering in &orderings {
                let assertion = inputs
                    .assertions()
                    .iter()
                    .find(|assertion| assertion.order() == ordering.data.witness_order())
                    .unwrap();
                assert_eq!(ordering.data.obligation_source(), assertion.source());
                assert_eq!(ordering.data.endpoint(), &assertion.owner().erase());
                assert_eq!(ordering.data.trace_target(), assertion.trace().target());
                assert_eq!(ordering.data.trace(), assertion.trace());
                assert_eq!(
                    ordering.data.semantic_order().traversal_order(),
                    assertion.visit_order()
                );
            }
            assert!(
                inputs
                    .assertions()
                    .iter()
                    .any(|assertion| assertion.visit_order() != assertion.order())
            );
            let attachment = &attachments[0].data;
            let witness = reachable
                .iter()
                .find(|row| row.data.witness_order() == attachment.witness_order())
                .unwrap();
            assert_eq!(attachment.obligation_source(), witness.data.assertion());
            assert_eq!(attachment.endpoint(), witness.data.endpoint());
            assert_eq!(attachment.group(), witness.data.endpoint());
            assert_eq!(attachment.trace(), witness.data.trace());
            assert_eq!(attachment.resolved_requirements().len(), 1);
            assert_eq!(
                attachment.claim(),
                &inputs.assertions()[0].markers()[0].claim().erase()
            );
        });
    }

    #[test]
    fn empty_root_emits_no_evaluation_delta() {
        with_inputs(0, false, |registry, _, workspace, inputs, graph| {
            let mut evaluated = EvaluationDb::new();
            run_ingress(registry, workspace, &inputs, graph, &mut evaluated).unwrap();

            assert_eq!(evaluated.derived_count(), 0);
            assert_eq!(evaluated.issue_count(), 0);
        });
    }

    #[test]
    fn malformed_later_order_discards_the_whole_fresh_delta() {
        with_inputs(2, false, |registry, _, workspace, mut inputs, graph| {
            inputs.test_assertion_mut(1).unwrap().test_set_order(7);
            let mut evaluated = EvaluationDb::new();

            let error = run_ingress(registry, workspace, &inputs, graph, &mut evaluated)
                .expect_err("a non-dense later witness must fail the entire rule");

            assert!(error.to_string().contains("not dense"));
            assert_eq!(evaluated.derived_count(), 0);
            assert_eq!(evaluated.issue_count(), 0);
        });
    }

    #[test]
    fn altered_assertion_fact_projection_is_rejected_before_emission() {
        with_inputs(1, false, |registry, _, workspace, mut inputs, graph| {
            inputs
                .test_assertion_mut(0)
                .unwrap()
                .test_set_kind(MirAssertKind::DivisionByZero);
            let mut evaluated = EvaluationDb::new();

            let error = run_ingress(registry, workspace, &inputs, graph, &mut evaluated)
                .expect_err("a projected kind must match the permanent fact");

            assert!(error.to_string().contains("kind disagrees"));
            assert_eq!(evaluated.derived_count(), 0);
        });
    }

    #[test]
    fn altered_assertion_source_is_rejected_before_emission() {
        with_inputs(2, false, |registry, _, workspace, mut inputs, graph| {
            let first_source = inputs.assertions()[0].source().clone();
            inputs
                .test_assertion_mut(1)
                .unwrap()
                .test_set_source(first_source);
            let mut evaluated = EvaluationDb::new();

            let error = run_ingress(registry, workspace, &inputs, graph, &mut evaluated)
                .expect_err("the source row must retain its exact owner");

            assert!(error.to_string().contains("owner disagrees"));
            assert_eq!(evaluated.derived_count(), 0);
        });
    }

    #[test]
    fn altered_assertion_owner_is_rejected_before_emission() {
        with_inputs(2, false, |registry, _, workspace, mut inputs, graph| {
            let first_owner = inputs.assertions()[0].owner().clone();
            inputs
                .test_assertion_mut(1)
                .unwrap()
                .test_set_owner(first_owner);
            let mut evaluated = EvaluationDb::new();

            let error = run_ingress(registry, workspace, &inputs, graph, &mut evaluated)
                .expect_err("the endpoint must retain the fact's exact effect owner");

            assert!(error.to_string().contains("owner disagrees"));
            assert_eq!(evaluated.derived_count(), 0);
        });
    }

    #[test]
    fn altered_assertion_trace_is_rejected_before_emission() {
        with_inputs(1, false, |registry, _, workspace, mut inputs, graph| {
            let root = inputs.root().entity.clone();
            inputs
                .test_assertion_mut(0)
                .unwrap()
                .test_set_trace(RelationTrace::new(root.clone(), root, Vec::new()));
            let mut evaluated = EvaluationDb::new();

            let error = run_ingress(registry, workspace, &inputs, graph, &mut evaluated)
                .expect_err("the obligation trace must equal the resolved effect trace");

            assert!(error.to_string().contains("route metadata disagrees"));
            assert_eq!(evaluated.derived_count(), 0);
        });
    }

    #[test]
    fn altered_requirements_are_rejected_before_emission() {
        with_inputs(1, false, |registry, _, workspace, mut inputs, graph| {
            inputs
                .test_assertion_mut(0)
                .unwrap()
                .test_clear_requirements();
            let mut evaluated = EvaluationDb::new();

            let error = run_ingress(registry, workspace, &inputs, graph, &mut evaluated)
                .expect_err("requirements must match the permanent fact exactly");

            assert!(error.to_string().contains("requirements disagree"));
            assert_eq!(evaluated.derived_count(), 0);
        });
    }

    #[test]
    fn altered_marker_data_is_rejected_before_emission() {
        with_inputs(1, true, |registry, _, workspace, mut inputs, graph| {
            let original = inputs.assertions()[0].markers()[0].data();
            let altered = MarkerClaimEntity::new(
                original.key().clone(),
                original.selector().clone(),
                "altered rationale",
            );
            inputs
                .test_assertion_mut(0)
                .unwrap()
                .test_marker_mut(0)
                .unwrap()
                .test_set_data(altered);
            let mut evaluated = EvaluationDb::new();

            let error = run_ingress(registry, workspace, &inputs, graph, &mut evaluated)
                .expect_err("marker data must remain identical to active traversal state");

            assert!(error.to_string().contains("marker identity, data"));
            assert_eq!(evaluated.derived_count(), 0);
        });
    }

    #[test]
    fn altered_marker_activation_trace_is_rejected_before_emission() {
        with_inputs(1, true, |registry, _, workspace, mut inputs, graph| {
            let altered = inputs.assertions()[0].trace().clone();
            inputs
                .test_assertion_mut(0)
                .unwrap()
                .test_marker_mut(0)
                .unwrap()
                .test_set_trace(altered);
            let mut evaluated = EvaluationDb::new();

            let error = run_ingress(registry, workspace, &inputs, graph, &mut evaluated)
                .expect_err("marker activation must retain its exact resolved route");

            assert!(error.to_string().contains("activation trace was altered"));
            assert_eq!(evaluated.derived_count(), 0);
        });
    }

    #[test]
    fn replacement_workspace_rejects_prepared_inputs() {
        with_inputs(1, false, |registry, artifact, _, inputs, _| {
            let scope = inputs.root().entity.scope().clone();
            let replacement = WorkspaceFactView::compose([(
                scope,
                ArtifactDbView::open(artifact, registry.schemas()).unwrap(),
            )])
            .unwrap();
            let composition = CompositionRelationBuilder::new(
                inputs.root(),
                &replacement,
                registry.composition_relations(),
            )
            .unwrap()
            .finalize()
            .unwrap();
            let evaluation =
                WorkspaceEvaluationView::open(inputs.root(), &replacement, &composition).unwrap();
            let mut evaluated = EvaluationDb::new();

            let error = registry
                .run_workspace_evaluation(&inputs, inputs.root(), &evaluation, &mut evaluated)
                .expect_err("replacement workspace identities must not be interchangeable");

            assert!(error.to_string().contains("replacement workspace"));
            assert_eq!(evaluated.derived_count(), 0);
        });
    }

    #[test]
    fn different_evaluation_root_rejects_prepared_inputs() {
        with_inputs(1, false, |registry, _, workspace, inputs, _| {
            let other_root = EvaluationRoot::new(
                DomainId::new("sniff-test.other-domain").unwrap(),
                inputs.root().entity.clone(),
            );
            let composition = CompositionRelationBuilder::new(
                &other_root,
                workspace,
                registry.composition_relations(),
            )
            .unwrap()
            .finalize()
            .unwrap();
            let evaluation =
                WorkspaceEvaluationView::open(&other_root, workspace, &composition).unwrap();
            let mut evaluated = EvaluationDb::new();

            let error = registry
                .run_workspace_evaluation(&inputs, &other_root, &evaluation, &mut evaluated)
                .expect_err("root-specific inputs must not run for another domain/root");

            assert!(error.to_string().contains("different evaluation root"));
            assert_eq!(evaluated.derived_count(), 0);
        });
    }

    #[test]
    fn pack_registers_one_stable_rule() {
        let registry = registry();
        let descriptor = registry
            .evaluation_rules()
            .descriptor(&PassId::new(EMIT_COMPILER_ASSERT_INPUTS_RULE).unwrap())
            .unwrap();

        assert_eq!(descriptor.reads().count(), 4);
        assert_eq!(descriptor.writes().count(), 3);
        assert_eq!(MirAssertFact::ID, "sniff-test.panic.mir-assert");
    }

    #[test]
    fn semantic_labels_preserve_legacy_macro_prefix_and_public_overflow_kind() {
        assert_eq!(
            semantic_node_label(CompilerAssertSemanticNodeRole::Macro, Some("macro raw!")).unwrap(),
            "macro macro raw!"
        );
        assert_eq!(
            semantic_node_label(
                CompilerAssertSemanticNodeRole::CompilerAssert(MirAssertKind::Overflow(
                    crate::analysis::facts::panic::model::BinaryOverflowOperation::Addition,
                )),
                None,
            )
            .unwrap(),
            "compiler assert arithmetic overflow"
        );
    }
}
