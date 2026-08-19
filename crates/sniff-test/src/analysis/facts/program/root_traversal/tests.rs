use std::collections::BTreeMap;
use std::convert::Infallible;

use super::*;
use crate::analysis::collected::CollectedArtifact;
use crate::analysis::facts::builder::ArtifactDbBuilder;
use crate::analysis::facts::composition::{
    CompositionRelationBuilder, CompositionRelationRegistry, WorkspaceRelationGraph,
};
use crate::analysis::facts::encoded::ArtifactFactIr;
use crate::analysis::facts::human::EvidenceClaimSelector;
use crate::analysis::facts::human::markers::{
    CallOccurrenceHasMarkerClaimCandidate, EffectSiteHasMarkerClaimCandidate,
    FunctionHasMarkerClaimCandidate, HumanMarkerCollectionPack, MarkerClaimEntity, MarkerClaimKey,
    MarkerOccurrenceEntity, MarkerOccurrenceHasClaim, MarkerOccurrenceHasSourceAnchor,
    MarkerOccurrenceKey, UnsafeOperationHasMarkerClaimCandidate,
};
use crate::analysis::facts::pack::AnalysisRegistry;
use crate::analysis::facts::panic::contract_collector::PanicContractCollectionPack;
use crate::analysis::facts::program::collector::CoreProgramCollectionPack;
use crate::analysis::facts::program::topology::{
    CallMacroExpansionEntersCallMacroExpansion, CallMacroExpansionEntity,
    CallMacroExpansionHasCallsite, CallMacroExpansionKey, CallMacroExpansionProducesCallOccurrence,
    CallOccurrenceEntity, CallOccurrenceHasCallableKey, CallOccurrenceHasSourceAnchor,
    CallOccurrenceInSafetyEffectGroup, CallOccurrenceKey, CallOccurrenceTargetsCallable,
    CallSiteEntity, CallSiteHasOccurrence, CallSiteKey, CallSourceAnchorRole, CallTargetRole,
    CallableEntity, CallableKey, CallableKeyEntity, FunctionDefinesCallable,
    FunctionEntersCallMacroExpansion, FunctionOwnsCallSite, FunctionOwnsSafetyEffectGroup,
    SafetyEffectGroupEntity, SafetyEffectGroupKey,
};
use crate::analysis::facts::program::workspace_index::VerifiedArtifactOwner;
use crate::analysis::facts::program::{
    EffectSiteEntity, EffectSiteHasSourceAnchor, EffectSiteKey, EffectSourceAnchorRole,
    FunctionBodyProvenance, FunctionEntersMacroExpansion, FunctionOwnsEffectSite,
    MacroExpansionEntersMacroExpansion, MacroExpansionEntity, MacroExpansionHasCallsite,
    MacroExpansionKey, MacroExpansionProducesEffectSite, SourceAnchorEntity, SourceAnchorInFile,
    SourceAnchorKey, SourceFileEntity,
};
use crate::analysis::facts::safety::collector::SafetyCollectionPack;
use crate::analysis::facts::safety::operations::{
    FunctionEntersUnsafeOperationMacroExpansion, FunctionOwnsUnsafeOperation, SafetyOperationKind,
    UnsafeOperationEntity, UnsafeOperationHasSourceAnchor, UnsafeOperationInSafetyEffectGroup,
    UnsafeOperationKey, UnsafeOperationMacroExpansionEntersUnsafeOperationMacroExpansion,
    UnsafeOperationMacroExpansionEntity, UnsafeOperationMacroExpansionHasCallsite,
    UnsafeOperationMacroExpansionKey, UnsafeOperationMacroExpansionProducesUnsafeOperation,
    UnsafeOperationSourceAnchorRole,
};
use crate::analysis::facts::schema::EntityHandle;
use crate::analysis::facts::view::ArtifactDbView;
use crate::analysis::facts::workspace::{ScopedEntityRef, WorkspaceFactView};
use crate::namespace::{
    StableDefPathHash, StableExpansionHash, StableInstanceHash, StableTypeHash,
};
use reachability::MirBodyLocation;

fn definition(stable_crate_id: u64, local: u64) -> StableDefPathHash {
    serde_json::from_str(&format!("\"{stable_crate_id:016x}{local:016x}\""))
        .expect("valid definition hash")
}

fn instance(value: u128) -> StableInstanceHash {
    serde_json::from_str(&format!("\"{value:032x}\"")).expect("valid instance hash")
}

fn expansion(value: u128) -> StableExpansionHash {
    serde_json::from_str(&format!("\"{value:032x}\"")).expect("valid expansion hash")
}

fn type_hash(value: u128) -> StableTypeHash {
    serde_json::from_str(&format!("\"{value:032x}\"")).expect("valid type hash")
}

fn registry() -> AnalysisRegistry<CollectedArtifact> {
    let mut registry = AnalysisRegistry::new();
    registry.install(&CoreProgramCollectionPack).unwrap();
    registry.install(&PanicContractCollectionPack).unwrap();
    registry.install(&SafetyCollectionPack).unwrap();
    registry.install(&HumanMarkerCollectionPack).unwrap();
    registry
}

fn root_artifact(
    registry: &AnalysisRegistry<CollectedArtifact>,
    functions: &[(FunctionKey, FunctionBodyProvenance)],
) -> ArtifactFactIr {
    let mut builder = ArtifactDbBuilder::new();
    for descriptor in registry.schemas().descriptors() {
        builder.declare_table(descriptor).unwrap();
    }
    for (key, provenance) in functions {
        let body = builder
            .insert_entity(&FunctionEntity::new(*key, "crate::root", *provenance))
            .unwrap();
        let callable = builder
            .insert_entity(&CallableEntity::new(
                *key,
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
    }
    builder.finalize(registry.schemas()).unwrap()
}

fn direct_effect_artifact(
    registry: &AnalysisRegistry<CollectedArtifact>,
    root: FunctionKey,
    sites: &[(u32, u32)],
) -> ArtifactFactIr {
    let mut builder = ArtifactDbBuilder::new();
    for descriptor in registry.schemas().descriptors() {
        builder.declare_table(descriptor).unwrap();
    }
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
    for &(basic_block, statement_index) in sites {
        let site = EffectSiteKey::from_mir(
            root,
            MirBodyLocation {
                basic_block: basic_block as usize,
                statement_index: statement_index as usize,
            },
        )
        .unwrap();
        let effect = builder.insert_entity(&EffectSiteEntity::new(site)).unwrap();
        builder
            .relate(&body, &effect, &FunctionOwnsEffectSite::new())
            .unwrap();
    }
    builder.finalize(registry.schemas()).unwrap()
}

fn request(domain: &str, scope: ArtifactScopeId, root: FunctionKey) -> RootProgramTraversalRequest {
    RootProgramTraversalRequest::new(
        DomainId::new(domain).unwrap(),
        scope,
        root,
        CallAttributionRole::CallSite,
        MarkerProbe::SourceCallsite,
        16,
    )
}

#[test]
fn cached_unsafe_macro_path_shape_rejects_empty_and_misaligned_routes_without_indexing() {
    assert!(!engine::validate_unsafe_operation_path_shape(0, 0));
    assert!(!engine::validate_unsafe_operation_path_shape(2, 0));
    assert!(!engine::validate_unsafe_operation_path_shape(2, 2));
    assert!(engine::validate_unsafe_operation_path_shape(1, 0));
    assert!(engine::validate_unsafe_operation_path_shape(2, 1));
}

fn resolve_prepared(
    prepared: PreparedRootProgramTraversal<&'static str, Infallible>,
    workspace: &WorkspaceFactView<'_>,
    registry: &AnalysisRegistry<CollectedArtifact>,
) -> ResolvedRootProgramTraversal<&'static str> {
    let mut builder = CompositionRelationBuilder::new(
        prepared.root(),
        workspace,
        registry.composition_relations(),
    )
    .unwrap();
    let emitted = prepared.emit(&mut builder).unwrap();
    let composition = builder.finalize().unwrap();
    let graph = WorkspaceRelationGraph::new(emitted.root(), workspace, &composition).unwrap();
    emitted
        .resolve(&graph, registry.composition_relations())
        .unwrap()
}

fn direct_call_artifact(
    registry: &AnalysisRegistry<CollectedArtifact>,
    root: FunctionKey,
    target: FunctionKey,
) -> crate::analysis::facts::encoded::ArtifactFactIr {
    let mut builder = ArtifactDbBuilder::new();
    for descriptor in registry.schemas().descriptors() {
        builder.declare_table(descriptor).unwrap();
    }
    let root_body = builder
        .insert_entity(&FunctionEntity::new(
            root,
            "crate::root",
            FunctionBodyProvenance::DefiningArtifact,
        ))
        .unwrap();
    let root_callable = builder
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
        .relate(&root_body, &root_callable, &FunctionDefinesCallable::new())
        .unwrap();
    let target_body = builder
        .insert_entity(&FunctionEntity::new(
            target,
            "crate::target",
            FunctionBodyProvenance::DefiningArtifact,
        ))
        .unwrap();
    let target_callable = builder
        .insert_entity(&CallableEntity::new(
            target,
            "crate::target",
            false,
            false,
            true,
            false,
            vec![String::from("crate::target")],
        ))
        .unwrap();
    builder
        .relate(
            &target_body,
            &target_callable,
            &FunctionDefinesCallable::new(),
        )
        .unwrap();

    let site = builder
        .insert_entity(&CallSiteEntity::new(CallSiteKey::new(root, 0)))
        .unwrap();
    builder
        .relate(&root_body, &site, &FunctionOwnsCallSite::new())
        .unwrap();
    let occurrence = builder
        .insert_entity(&CallOccurrenceEntity::new(
            CallOccurrenceKey::new(root, 0),
            CallKind::DirectCall,
            vec![CallAttributionRole::CallSite],
            false,
            false,
            None,
        ))
        .unwrap();
    builder
        .relate(&site, &occurrence, &CallSiteHasOccurrence::new())
        .unwrap();
    builder
        .relate(
            &occurrence,
            &target_callable,
            &CallOccurrenceTargetsCallable::new(CallTargetRole::Runtime),
        )
        .unwrap();
    let group = builder
        .insert_entity(&SafetyEffectGroupEntity::new(SafetyEffectGroupKey::new(
            root, 0,
        )))
        .unwrap();
    builder
        .relate(&root_body, &group, &FunctionOwnsSafetyEffectGroup::new())
        .unwrap();
    builder
        .relate(
            &occurrence,
            &group,
            &CallOccurrenceInSafetyEffectGroup::new(),
        )
        .unwrap();
    builder.finalize(registry.schemas()).unwrap()
}

#[derive(Clone, Copy)]
enum MarkerEndpoint {
    Function,
    Call,
}

#[derive(Clone, Copy)]
enum MarkerMatch {
    SourceCallsite,
    MacroDefinitionFirst,
}

#[derive(Clone, Copy)]
enum TargetFixture {
    None,
    Root,
    SeparateWithBody,
    SeparateWithoutBody,
}

#[derive(Clone, Copy)]
enum CallRoute {
    Site,
    Macro,
}

struct ConfiguredCall {
    kind: CallKind,
    attribution: Vec<CallAttributionRole>,
    callable_key: Option<CallableKey>,
    target: TargetFixture,
    call_count: u32,
    route: CallRoute,
    marker: Option<(MarkerEndpoint, &'static str, MarkerMatch)>,
}

fn configured_call_artifact(
    registry: &AnalysisRegistry<CollectedArtifact>,
    root: FunctionKey,
    target: FunctionKey,
    config: &ConfiguredCall,
) -> crate::analysis::facts::encoded::ArtifactFactIr {
    let mut artifact = ConfiguredCallArtifactBuilder::new(registry, root);
    let target = artifact.insert_target(target, config.target);
    let first_occurrence = artifact.insert_calls(config, target.as_ref());
    if let Some((endpoint, domain, marker_match)) = config.marker {
        artifact.insert_marker(endpoint, domain, marker_match, first_occurrence.as_ref());
    }
    artifact.finish(registry)
}

struct ConfiguredCallArtifactBuilder {
    builder: ArtifactDbBuilder,
    file: EntityHandle<SourceFileEntity>,
    anchor_key: SourceAnchorKey,
    anchor: EntityHandle<SourceAnchorEntity>,
    root_body: EntityHandle<FunctionEntity>,
    root_callable: EntityHandle<CallableEntity>,
    bodies: BTreeMap<FunctionKey, EntityHandle<FunctionEntity>>,
    safety_groups: BTreeMap<SafetyEffectGroupKey, EntityHandle<SafetyEffectGroupEntity>>,
    next_anchor: u32,
}

impl ConfiguredCallArtifactBuilder {
    fn new(registry: &AnalysisRegistry<CollectedArtifact>, root: FunctionKey) -> Self {
        Self::new_with_provenance(registry, root, FunctionBodyProvenance::DefiningArtifact)
    }

    fn new_with_provenance(
        registry: &AnalysisRegistry<CollectedArtifact>,
        root: FunctionKey,
        provenance: FunctionBodyProvenance,
    ) -> Self {
        let mut builder = ArtifactDbBuilder::new();
        for descriptor in registry.schemas().descriptors() {
            builder.declare_table(descriptor).unwrap();
        }
        let file = builder
            .insert_entity(&SourceFileEntity::new(
                "src/lib.rs",
                "src/lib.rs",
                "verified-hash",
                100,
            ))
            .unwrap();
        let anchor_key = SourceAnchorKey::new("src/lib.rs", 0, 10);
        let anchor = builder
            .insert_entity(&SourceAnchorEntity::new(anchor_key.clone()))
            .unwrap();
        builder
            .relate(&anchor, &file, &SourceAnchorInFile::new())
            .unwrap();
        let root_body = builder
            .insert_entity(&FunctionEntity::new(root, "crate::root", provenance))
            .unwrap();
        let root_callable = builder
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
            .relate(&root_body, &root_callable, &FunctionDefinesCallable::new())
            .unwrap();
        let bodies = BTreeMap::from([(root, root_body.clone())]);
        Self {
            builder,
            file,
            anchor_key,
            anchor,
            root_body,
            root_callable,
            bodies,
            safety_groups: BTreeMap::new(),
            next_anchor: 1,
        }
    }

    fn insert_target(
        &mut self,
        target: FunctionKey,
        fixture: TargetFixture,
    ) -> Option<EntityHandle<CallableEntity>> {
        match fixture {
            TargetFixture::Root => Some(self.root_callable.clone()),
            TargetFixture::None => None,
            TargetFixture::SeparateWithBody | TargetFixture::SeparateWithoutBody => {
                let callable = self
                    .builder
                    .insert_entity(&CallableEntity::new(
                        target,
                        "crate::target",
                        false,
                        false,
                        matches!(fixture, TargetFixture::SeparateWithBody),
                        false,
                        vec![String::from("crate::target")],
                    ))
                    .unwrap();
                if matches!(fixture, TargetFixture::SeparateWithBody) {
                    let target_body = self
                        .builder
                        .insert_entity(&FunctionEntity::new(
                            target,
                            "crate::target",
                            FunctionBodyProvenance::DefiningArtifact,
                        ))
                        .unwrap();
                    self.builder
                        .relate(&target_body, &callable, &FunctionDefinesCallable::new())
                        .unwrap();
                    self.bodies.insert(target, target_body);
                }
                Some(callable)
            }
        }
    }

    fn insert_consumer_target(
        &mut self,
        target: FunctionKey,
        consumer_stable_crate_id: u64,
    ) -> EntityHandle<CallableEntity> {
        let callable = self
            .builder
            .insert_entity(&CallableEntity::new(
                target,
                "crate::consumer",
                false,
                false,
                true,
                false,
                vec![String::from("crate::consumer")],
            ))
            .unwrap();
        let body = self
            .builder
            .insert_entity(&FunctionEntity::new(
                target,
                "crate::consumer",
                FunctionBodyProvenance::ConsumerInstantiation {
                    consumer_stable_crate_id,
                },
            ))
            .unwrap();
        self.builder
            .relate(&body, &callable, &FunctionDefinesCallable::new())
            .unwrap();
        self.bodies.insert(target, body);
        callable
    }

    fn insert_effect(
        &mut self,
        owner: FunctionKey,
        basic_block: u32,
        statement_index: u32,
    ) -> EntityHandle<EffectSiteEntity> {
        let body = self
            .bodies
            .get(&owner)
            .expect("effect owner body exists")
            .clone();
        let key = EffectSiteKey::from_mir(
            owner,
            MirBodyLocation {
                basic_block: basic_block as usize,
                statement_index: statement_index as usize,
            },
        )
        .unwrap();
        let effect = self
            .builder
            .insert_entity(&EffectSiteEntity::new(key))
            .unwrap();
        self.builder
            .relate(&body, &effect, &FunctionOwnsEffectSite::new())
            .unwrap();
        effect
    }

    fn insert_unsafe_operation(
        &mut self,
        owner: FunctionKey,
        local_id: u32,
        kind: SafetyOperationKind,
    ) -> EntityHandle<UnsafeOperationEntity> {
        let body = self.bodies.get(&owner).unwrap().clone();
        let group = self.safety_group(owner, local_id);
        let operation = self
            .builder
            .insert_entity(&UnsafeOperationEntity::new(
                UnsafeOperationKey::new(owner, local_id),
                kind,
            ))
            .unwrap();
        self.builder
            .relate(&body, &operation, &FunctionOwnsUnsafeOperation::new())
            .unwrap();
        self.builder
            .relate(
                &operation,
                &group,
                &UnsafeOperationInSafetyEffectGroup::new(),
            )
            .unwrap();
        operation
    }

    fn safety_group(
        &mut self,
        owner: FunctionKey,
        local_id: u32,
    ) -> EntityHandle<SafetyEffectGroupEntity> {
        let key = SafetyEffectGroupKey::new(owner, local_id);
        if let Some(group) = self.safety_groups.get(&key) {
            return group.clone();
        }
        let body = self.bodies.get(&owner).unwrap().clone();
        let group = self
            .builder
            .insert_entity(&SafetyEffectGroupEntity::new(key))
            .unwrap();
        self.builder
            .relate(&body, &group, &FunctionOwnsSafetyEffectGroup::new())
            .unwrap();
        self.safety_groups.insert(key, group.clone());
        group
    }

    fn attach_unsafe_operation_source_anchor(
        &mut self,
        operation: &EntityHandle<UnsafeOperationEntity>,
        role: UnsafeOperationSourceAnchorRole,
        anchor: &EntityHandle<SourceAnchorEntity>,
    ) {
        self.builder
            .relate(
                operation,
                anchor,
                &UnsafeOperationHasSourceAnchor::new(role),
            )
            .unwrap();
    }

    fn insert_unsafe_operation_macro_route(
        &mut self,
        operation: &EntityHandle<UnsafeOperationEntity>,
        callsites: &[Option<EntityHandle<SourceAnchorEntity>>],
    ) {
        assert!(!callsites.is_empty());
        let key = *operation.key();
        let owner = self.bodies.get(key.owner()).unwrap().clone();
        let mut frames = Vec::with_capacity(callsites.len());
        for (depth, callsite) in (0_u32..).zip(callsites) {
            let frame = self
                .builder
                .insert_entity(&UnsafeOperationMacroExpansionEntity::new(
                    UnsafeOperationMacroExpansionKey::new(key, depth),
                    expansion(20_000 + u128::from(depth)),
                    definition(98, u64::from(depth) + 1),
                    format!("crate::unsafe_macro_{depth}"),
                ))
                .unwrap();
            if let Some(anchor) = callsite {
                self.builder
                    .relate(
                        &frame,
                        anchor,
                        &UnsafeOperationMacroExpansionHasCallsite::new(),
                    )
                    .unwrap();
            }
            frames.push(frame);
        }
        self.builder
            .relate(
                &owner,
                &frames[0],
                &FunctionEntersUnsafeOperationMacroExpansion::new(),
            )
            .unwrap();
        for pair in frames.windows(2) {
            self.builder
                .relate(
                    &pair[0],
                    &pair[1],
                    &UnsafeOperationMacroExpansionEntersUnsafeOperationMacroExpansion::new(),
                )
                .unwrap();
        }
        self.builder
            .relate(
                frames.last().unwrap(),
                operation,
                &UnsafeOperationMacroExpansionProducesUnsafeOperation::new(),
            )
            .unwrap();
    }

    fn attach_unsafe_operation_marker(
        &mut self,
        operation: &EntityHandle<UnsafeOperationEntity>,
        domain: &'static str,
        marker_match: MarkerMatch,
    ) -> EntityHandle<MarkerClaimEntity> {
        let (anchor_key, anchor) = self.insert_anchor();
        let marker_key = MarkerOccurrenceKey::new(anchor_key, None);
        let marker = self
            .builder
            .insert_entity(&MarkerOccurrenceEntity::new(marker_key.clone(), Vec::new()))
            .unwrap();
        self.builder
            .relate(&marker, &anchor, &MarkerOccurrenceHasSourceAnchor::new())
            .unwrap();
        let claim = self
            .builder
            .insert_entity(&MarkerClaimEntity::new(
                MarkerClaimKey::new(marker_key, DomainId::new(domain).unwrap(), 0),
                EvidenceClaimSelector::Unnamed,
                "unsafe-operation marker",
            ))
            .unwrap();
        self.builder
            .relate(&marker, &claim, &MarkerOccurrenceHasClaim::new())
            .unwrap();
        let (source_callsite, macro_definition_first) = match marker_match {
            MarkerMatch::SourceCallsite => (true, false),
            MarkerMatch::MacroDefinitionFirst => (false, true),
        };
        self.builder
            .relate(
                operation,
                &claim,
                &UnsafeOperationHasMarkerClaimCandidate::new(
                    source_callsite,
                    macro_definition_first,
                ),
            )
            .unwrap();
        claim
    }

    fn insert_anchor(&mut self) -> (SourceAnchorKey, EntityHandle<SourceAnchorEntity>) {
        let start = u64::from(20 + self.next_anchor * 5);
        self.next_anchor += 1;
        let key = SourceAnchorKey::new("src/lib.rs", start, start + 3);
        let anchor = self
            .builder
            .insert_entity(&SourceAnchorEntity::new(key.clone()))
            .unwrap();
        self.builder
            .relate(&anchor, &self.file, &SourceAnchorInFile::new())
            .unwrap();
        (key, anchor)
    }

    fn attach_effect_source_anchor(
        &mut self,
        effect: &EntityHandle<EffectSiteEntity>,
        role: EffectSourceAnchorRole,
        anchor: &EntityHandle<SourceAnchorEntity>,
    ) {
        self.builder
            .relate(effect, anchor, &EffectSiteHasSourceAnchor::new(role))
            .unwrap();
    }

    fn insert_effect_macro_route(
        &mut self,
        effect: &EntityHandle<EffectSiteEntity>,
        callsites: &[Option<EntityHandle<SourceAnchorEntity>>],
    ) {
        assert!(
            !callsites.is_empty(),
            "test macro route has at least one frame"
        );
        let site = *effect.key();
        let owner = self
            .bodies
            .get(site.function())
            .expect("macro effect owner body exists")
            .clone();
        let mut frames = Vec::with_capacity(callsites.len());
        for (depth, callsite) in (0_u32..).zip(callsites) {
            let frame = self
                .builder
                .insert_entity(&MacroExpansionEntity::new(
                    MacroExpansionKey::new(site, depth),
                    expansion(
                        10_000
                            + u128::from(site.basic_block()) * 1_000
                            + u128::from(site.statement_index()) * 10
                            + u128::from(depth),
                    ),
                    definition(99, u64::from(depth) + 1),
                    format!("crate::effect_macro_{depth}"),
                ))
                .unwrap();
            if let Some(anchor) = callsite {
                self.builder
                    .relate(&frame, anchor, &MacroExpansionHasCallsite::new())
                    .unwrap();
            }
            frames.push(frame);
        }
        self.builder
            .relate(&owner, &frames[0], &FunctionEntersMacroExpansion::new())
            .unwrap();
        for pair in frames.windows(2) {
            self.builder
                .relate(
                    &pair[0],
                    &pair[1],
                    &MacroExpansionEntersMacroExpansion::new(),
                )
                .unwrap();
        }
        self.builder
            .relate(
                frames.last().expect("nonempty macro frames"),
                effect,
                &MacroExpansionProducesEffectSite::new(),
            )
            .unwrap();
    }

    fn attach_effect_marker(
        &mut self,
        effect: &EntityHandle<EffectSiteEntity>,
        domain: &'static str,
        marker_match: MarkerMatch,
    ) -> EntityHandle<MarkerClaimEntity> {
        let (anchor_key, anchor) = self.insert_anchor();
        let marker_key = MarkerOccurrenceKey::new(anchor_key, None);
        let marker = self
            .builder
            .insert_entity(&MarkerOccurrenceEntity::new(marker_key.clone(), Vec::new()))
            .unwrap();
        self.builder
            .relate(&marker, &anchor, &MarkerOccurrenceHasSourceAnchor::new())
            .unwrap();
        let claim = self
            .builder
            .insert_entity(&MarkerClaimEntity::new(
                MarkerClaimKey::new(marker_key, DomainId::new(domain).unwrap(), 0),
                EvidenceClaimSelector::Unnamed,
                "effect marker",
            ))
            .unwrap();
        self.builder
            .relate(&marker, &claim, &MarkerOccurrenceHasClaim::new())
            .unwrap();
        let (source_callsite, macro_definition_first) = match marker_match {
            MarkerMatch::SourceCallsite => (true, false),
            MarkerMatch::MacroDefinitionFirst => (false, true),
        };
        self.builder
            .relate(
                effect,
                &claim,
                &EffectSiteHasMarkerClaimCandidate::new(source_callsite, macro_definition_first),
            )
            .unwrap();
        claim
    }

    fn insert_call_for(
        &mut self,
        owner: FunctionKey,
        local_id: u32,
        target: Option<&EntityHandle<CallableEntity>>,
    ) -> EntityHandle<CallOccurrenceEntity> {
        let body = self
            .bodies
            .get(&owner)
            .expect("call owner body exists")
            .clone();
        let group = self.safety_group(owner, local_id);
        let site = self
            .builder
            .insert_entity(&CallSiteEntity::new(CallSiteKey::new(owner, local_id)))
            .unwrap();
        self.builder
            .relate(&body, &site, &FunctionOwnsCallSite::new())
            .unwrap();
        let occurrence = self
            .builder
            .insert_entity(&CallOccurrenceEntity::new(
                CallOccurrenceKey::new(owner, local_id),
                CallKind::DirectCall,
                vec![CallAttributionRole::CallSite],
                false,
                false,
                target.is_none().then(|| String::from("opaque target")),
            ))
            .unwrap();
        self.builder
            .relate(&site, &occurrence, &CallSiteHasOccurrence::new())
            .unwrap();
        self.builder
            .relate(
                &occurrence,
                &group,
                &CallOccurrenceInSafetyEffectGroup::new(),
            )
            .unwrap();
        if let Some(target) = target {
            self.builder
                .relate(
                    &occurrence,
                    target,
                    &CallOccurrenceTargetsCallable::new(CallTargetRole::Runtime),
                )
                .unwrap();
        }
        occurrence
    }

    fn insert_keyed_call_for(
        &mut self,
        owner: FunctionKey,
        local_id: u32,
        kind: CallKind,
        attribution: Vec<CallAttributionRole>,
        callable_key: &EntityHandle<CallableKeyEntity>,
        targets: &[(CallTargetRole, EntityHandle<CallableEntity>)],
    ) -> EntityHandle<CallOccurrenceEntity> {
        let body = self
            .bodies
            .get(&owner)
            .expect("call owner body exists")
            .clone();
        let group = self
            .builder
            .insert_entity(&SafetyEffectGroupEntity::new(SafetyEffectGroupKey::new(
                owner, local_id,
            )))
            .unwrap();
        self.builder
            .relate(&body, &group, &FunctionOwnsSafetyEffectGroup::new())
            .unwrap();
        let site = self
            .builder
            .insert_entity(&CallSiteEntity::new(CallSiteKey::new(owner, local_id)))
            .unwrap();
        self.builder
            .relate(&body, &site, &FunctionOwnsCallSite::new())
            .unwrap();
        let occurrence = self
            .builder
            .insert_entity(&CallOccurrenceEntity::new(
                CallOccurrenceKey::new(owner, local_id),
                kind,
                attribution,
                false,
                false,
                (!targets
                    .iter()
                    .any(|(role, _)| *role == CallTargetRole::Runtime))
                .then(|| String::from("opaque target")),
            ))
            .unwrap();
        self.builder
            .relate(&site, &occurrence, &CallSiteHasOccurrence::new())
            .unwrap();
        self.builder
            .relate(
                &occurrence,
                &group,
                &CallOccurrenceInSafetyEffectGroup::new(),
            )
            .unwrap();
        self.builder
            .relate(
                &occurrence,
                callable_key,
                &CallOccurrenceHasCallableKey::new(),
            )
            .unwrap();
        for (role, target) in targets {
            self.builder
                .relate(
                    &occurrence,
                    target,
                    &CallOccurrenceTargetsCallable::new(*role),
                )
                .unwrap();
        }
        occurrence
    }

    fn insert_calls(
        &mut self,
        config: &ConfiguredCall,
        target: Option<&EntityHandle<CallableEntity>>,
    ) -> Option<EntityHandle<CallOccurrenceEntity>> {
        self.insert_calls_all(config, target).into_iter().next()
    }

    fn insert_calls_all(
        &mut self,
        config: &ConfiguredCall,
        target: Option<&EntityHandle<CallableEntity>>,
    ) -> Vec<EntityHandle<CallOccurrenceEntity>> {
        let root = *self.root_body.key();
        let group = self
            .builder
            .insert_entity(&SafetyEffectGroupEntity::new(SafetyEffectGroupKey::new(
                root, 0,
            )))
            .unwrap();
        self.builder
            .relate(
                &self.root_body,
                &group,
                &FunctionOwnsSafetyEffectGroup::new(),
            )
            .unwrap();
        let site = self
            .builder
            .insert_entity(&CallSiteEntity::new(CallSiteKey::new(root, 0)))
            .unwrap();
        self.builder
            .relate(&self.root_body, &site, &FunctionOwnsCallSite::new())
            .unwrap();
        let callable_key = config.callable_key.map(|key| {
            self.builder
                .insert_entity(&CallableKeyEntity::new(key))
                .unwrap()
        });
        let mut inserted = Vec::new();
        for local_id in 0..config.call_count {
            let occurrence_key = CallOccurrenceKey::new(root, local_id);
            let occurrence = self
                .builder
                .insert_entity(&CallOccurrenceEntity::new(
                    occurrence_key,
                    config.kind,
                    config.attribution.clone(),
                    false,
                    false,
                    target.is_none().then(|| String::from("opaque target")),
                ))
                .unwrap();
            inserted.push(occurrence.clone());
            self.builder
                .relate(&site, &occurrence, &CallSiteHasOccurrence::new())
                .unwrap();
            self.builder
                .relate(
                    &occurrence,
                    &group,
                    &CallOccurrenceInSafetyEffectGroup::new(),
                )
                .unwrap();
            if let Some(target) = target {
                self.builder
                    .relate(
                        &occurrence,
                        target,
                        &CallOccurrenceTargetsCallable::new(CallTargetRole::Runtime),
                    )
                    .unwrap();
            }
            if let Some(key) = &callable_key {
                self.builder
                    .relate(&occurrence, key, &CallOccurrenceHasCallableKey::new())
                    .unwrap();
            }
            if matches!(config.route, CallRoute::Macro) {
                self.insert_macro_route(occurrence_key, &occurrence, local_id);
            }
        }
        inserted
    }

    fn insert_macro_route(
        &mut self,
        occurrence_key: CallOccurrenceKey,
        occurrence: &EntityHandle<CallOccurrenceEntity>,
        local_id: u32,
    ) {
        let outer = self
            .builder
            .insert_entity(&CallMacroExpansionEntity::new(
                CallMacroExpansionKey::new(occurrence_key, 0),
                expansion(100 + u128::from(local_id)),
                definition(9, 1),
                "crate::outer_macro",
            ))
            .unwrap();
        let inner = self
            .builder
            .insert_entity(&CallMacroExpansionEntity::new(
                CallMacroExpansionKey::new(occurrence_key, 1),
                expansion(200 + u128::from(local_id)),
                definition(9, 2),
                "crate::inner_macro",
            ))
            .unwrap();
        self.builder
            .relate(
                &self.root_body,
                &outer,
                &FunctionEntersCallMacroExpansion::new(),
            )
            .unwrap();
        self.builder
            .relate(
                &outer,
                &inner,
                &CallMacroExpansionEntersCallMacroExpansion::new(),
            )
            .unwrap();
        self.builder
            .relate(
                &inner,
                occurrence,
                &CallMacroExpansionProducesCallOccurrence::new(),
            )
            .unwrap();
        self.builder
            .relate(&outer, &self.anchor, &CallMacroExpansionHasCallsite::new())
            .unwrap();
    }

    fn insert_marker(
        &mut self,
        endpoint: MarkerEndpoint,
        domain: &'static str,
        marker_match: MarkerMatch,
        first_occurrence: Option<&EntityHandle<CallOccurrenceEntity>>,
    ) -> EntityHandle<MarkerClaimEntity> {
        let (source_callsite, macro_definition_first) = match marker_match {
            MarkerMatch::SourceCallsite => (true, false),
            MarkerMatch::MacroDefinitionFirst => (false, true),
        };
        let marker_key = MarkerOccurrenceKey::new(self.anchor_key.clone(), None);
        let marker = self
            .builder
            .insert_entity(&MarkerOccurrenceEntity::new(marker_key.clone(), Vec::new()))
            .unwrap();
        self.builder
            .relate(
                &marker,
                &self.anchor,
                &MarkerOccurrenceHasSourceAnchor::new(),
            )
            .unwrap();
        let claim = self
            .builder
            .insert_entity(&MarkerClaimEntity::new(
                MarkerClaimKey::new(marker_key, DomainId::new(domain).unwrap(), 0),
                EvidenceClaimSelector::Unnamed,
                "test marker",
            ))
            .unwrap();
        self.builder
            .relate(&marker, &claim, &MarkerOccurrenceHasClaim::new())
            .unwrap();
        match endpoint {
            MarkerEndpoint::Function => self
                .builder
                .relate(
                    &self.root_body,
                    &claim,
                    &FunctionHasMarkerClaimCandidate::new(source_callsite, macro_definition_first),
                )
                .unwrap(),
            MarkerEndpoint::Call => self.attach_call_marker(
                first_occurrence.expect("marker fixture has an occurrence"),
                &claim,
                marker_match,
            ),
        }
        claim
    }

    fn attach_call_marker(
        &mut self,
        occurrence: &EntityHandle<CallOccurrenceEntity>,
        claim: &EntityHandle<MarkerClaimEntity>,
        marker_match: MarkerMatch,
    ) {
        let (source_callsite, macro_definition_first) = match marker_match {
            MarkerMatch::SourceCallsite => (true, false),
            MarkerMatch::MacroDefinitionFirst => (false, true),
        };
        self.builder
            .relate(
                occurrence,
                claim,
                &CallOccurrenceHasMarkerClaimCandidate::new(
                    source_callsite,
                    macro_definition_first,
                ),
            )
            .unwrap();
    }

    fn insert_call_marker_claim(
        &mut self,
        occurrence: &EntityHandle<CallOccurrenceEntity>,
        domain: &'static str,
    ) -> EntityHandle<MarkerClaimEntity> {
        let (anchor_key, anchor) = self.insert_anchor();
        let marker_key = MarkerOccurrenceKey::new(anchor_key, None);
        let marker = self
            .builder
            .insert_entity(&MarkerOccurrenceEntity::new(marker_key.clone(), Vec::new()))
            .unwrap();
        self.builder
            .relate(&marker, &anchor, &MarkerOccurrenceHasSourceAnchor::new())
            .unwrap();
        let claim = self
            .builder
            .insert_entity(&MarkerClaimEntity::new(
                MarkerClaimKey::new(marker_key, DomainId::new(domain).unwrap(), 0),
                EvidenceClaimSelector::Unnamed,
                "defining call marker",
            ))
            .unwrap();
        self.builder
            .relate(&marker, &claim, &MarkerOccurrenceHasClaim::new())
            .unwrap();
        self.attach_call_marker(occurrence, &claim, MarkerMatch::SourceCallsite);
        claim
    }

    fn attach_call_source_anchor(
        &mut self,
        occurrence: &EntityHandle<CallOccurrenceEntity>,
        role: CallSourceAnchorRole,
    ) {
        self.builder
            .relate(
                occurrence,
                &self.anchor,
                &CallOccurrenceHasSourceAnchor::new(role),
            )
            .unwrap();
    }

    fn finish(
        self,
        registry: &AnalysisRegistry<CollectedArtifact>,
    ) -> crate::analysis::facts::encoded::ArtifactFactIr {
        self.builder.finalize(registry.schemas()).unwrap()
    }
}

#[derive(Default)]
struct ExpandPolicy;

impl RootProgramTraversalPolicy for ExpandPolicy {
    type Error = Infallible;
    type Boundary = &'static str;

    fn decide_call(
        &mut self,
        _context: &CallPolicyContext<'_>,
    ) -> Result<CallTraversalDecision<Self::Boundary>, Self::Error> {
        Ok(CallTraversalDecision::Ignore)
    }

    fn decide_body(
        &mut self,
        _context: &BodyPolicyContext<'_>,
    ) -> Result<BodyTraversalDecision<Self::Boundary>, Self::Error> {
        Ok(BodyTraversalDecision::Expand)
    }

    fn defining_markers(
        &mut self,
        _context: &DefiningMarkerPolicyContext<'_>,
    ) -> Result<DefiningMarkerDecision, Self::Error> {
        Ok(DefiningMarkerDecision::RejectCompleteSet)
    }
}

#[derive(Default)]
struct FollowRuntimePolicy;

impl RootProgramTraversalPolicy for FollowRuntimePolicy {
    type Error = Infallible;
    type Boundary = &'static str;

    fn decide_call(
        &mut self,
        context: &CallPolicyContext<'_>,
    ) -> Result<CallTraversalDecision<Self::Boundary>, Self::Error> {
        Ok(CallTraversalDecision::Follow(
            context
                .targets
                .iter()
                .find(|target| target.role == CallTargetRole::Runtime)
                .expect("test call has a runtime target")
                .selection(),
        ))
    }

    fn decide_body(
        &mut self,
        _context: &BodyPolicyContext<'_>,
    ) -> Result<BodyTraversalDecision<Self::Boundary>, Self::Error> {
        Ok(BodyTraversalDecision::Expand)
    }

    fn defining_markers(
        &mut self,
        _context: &DefiningMarkerPolicyContext<'_>,
    ) -> Result<DefiningMarkerDecision, Self::Error> {
        Ok(DefiningMarkerDecision::RejectCompleteSet)
    }
}

#[derive(Default)]
struct FollowWhenTargetPolicy;

impl RootProgramTraversalPolicy for FollowWhenTargetPolicy {
    type Error = Infallible;
    type Boundary = &'static str;

    fn decide_call(
        &mut self,
        context: &CallPolicyContext<'_>,
    ) -> Result<CallTraversalDecision<Self::Boundary>, Self::Error> {
        Ok(context
            .targets
            .first()
            .map_or(CallTraversalDecision::Ignore, |target| {
                CallTraversalDecision::Follow(target.selection())
            }))
    }

    fn decide_body(
        &mut self,
        _context: &BodyPolicyContext<'_>,
    ) -> Result<BodyTraversalDecision<Self::Boundary>, Self::Error> {
        Ok(BodyTraversalDecision::Expand)
    }

    fn defining_markers(
        &mut self,
        _context: &DefiningMarkerPolicyContext<'_>,
    ) -> Result<DefiningMarkerDecision, Self::Error> {
        Ok(DefiningMarkerDecision::RejectCompleteSet)
    }
}

struct BoundaryPolicy;

impl RootProgramTraversalPolicy for BoundaryPolicy {
    type Error = Infallible;
    type Boundary = &'static str;

    fn decide_call(
        &mut self,
        _context: &CallPolicyContext<'_>,
    ) -> Result<CallTraversalDecision<Self::Boundary>, Self::Error> {
        Ok(CallTraversalDecision::Ignore)
    }

    fn decide_body(
        &mut self,
        _context: &BodyPolicyContext<'_>,
    ) -> Result<BodyTraversalDecision<Self::Boundary>, Self::Error> {
        Ok(BodyTraversalDecision::Boundary("boundary"))
    }

    fn defining_markers(
        &mut self,
        _context: &DefiningMarkerPolicyContext<'_>,
    ) -> Result<DefiningMarkerDecision, Self::Error> {
        Ok(DefiningMarkerDecision::RejectCompleteSet)
    }
}

struct IgnoreBodyPolicy;

impl RootProgramTraversalPolicy for IgnoreBodyPolicy {
    type Error = Infallible;
    type Boundary = &'static str;

    fn decide_call(
        &mut self,
        _context: &CallPolicyContext<'_>,
    ) -> Result<CallTraversalDecision<Self::Boundary>, Self::Error> {
        Ok(CallTraversalDecision::Ignore)
    }

    fn decide_body(
        &mut self,
        _context: &BodyPolicyContext<'_>,
    ) -> Result<BodyTraversalDecision<Self::Boundary>, Self::Error> {
        Ok(BodyTraversalDecision::Ignore)
    }

    fn defining_markers(
        &mut self,
        _context: &DefiningMarkerPolicyContext<'_>,
    ) -> Result<DefiningMarkerDecision, Self::Error> {
        Ok(DefiningMarkerDecision::RejectCompleteSet)
    }
}

struct CallBoundaryPolicy;

impl RootProgramTraversalPolicy for CallBoundaryPolicy {
    type Error = Infallible;
    type Boundary = &'static str;

    fn decide_call(
        &mut self,
        context: &CallPolicyContext<'_>,
    ) -> Result<CallTraversalDecision<Self::Boundary>, Self::Error> {
        Ok(CallTraversalDecision::Boundary {
            target: context
                .targets
                .first()
                .map(CallTargetPolicyCandidate::selection),
            payload: "call boundary",
        })
    }

    fn decide_body(
        &mut self,
        _context: &BodyPolicyContext<'_>,
    ) -> Result<BodyTraversalDecision<Self::Boundary>, Self::Error> {
        Ok(BodyTraversalDecision::Expand)
    }

    fn defining_markers(
        &mut self,
        _context: &DefiningMarkerPolicyContext<'_>,
    ) -> Result<DefiningMarkerDecision, Self::Error> {
        Ok(DefiningMarkerDecision::RejectCompleteSet)
    }
}

struct FollowAndBoundaryPolicy;

impl RootProgramTraversalPolicy for FollowAndBoundaryPolicy {
    type Error = Infallible;
    type Boundary = &'static str;

    fn decide_call(
        &mut self,
        context: &CallPolicyContext<'_>,
    ) -> Result<CallTraversalDecision<Self::Boundary>, Self::Error> {
        let selection = context
            .targets
            .first()
            .expect("test call has a target")
            .selection();
        Ok(CallTraversalDecision::FollowAndBoundary {
            follow: selection.clone(),
            boundary_target: Some(selection),
            payload: "followed call boundary",
        })
    }

    fn decide_body(
        &mut self,
        _context: &BodyPolicyContext<'_>,
    ) -> Result<BodyTraversalDecision<Self::Boundary>, Self::Error> {
        Ok(BodyTraversalDecision::Expand)
    }

    fn defining_markers(
        &mut self,
        _context: &DefiningMarkerPolicyContext<'_>,
    ) -> Result<DefiningMarkerDecision, Self::Error> {
        Ok(DefiningMarkerDecision::RejectCompleteSet)
    }
}

#[derive(Default)]
struct ObservingFollowPolicy {
    body_marker_counts: Vec<(usize, usize)>,
    call_marker_counts: Vec<(usize, usize, usize)>,
}

fn assert_exact_call_marker_activation(
    visit: &ResolvedOccurrenceVisit,
    indexed_candidate: &crate::analysis::facts::program::workspace_index::IndexedMarkerCandidate,
    indexed_claim_data: &MarkerClaimEntity,
) {
    let [activation] = visit.attached_marker_candidates() else {
        panic!("the call must retain exactly one attached marker candidate");
    };
    assert_eq!(activation.claim(), indexed_candidate.claim_id());
    assert_eq!(activation.data(), indexed_claim_data);
    assert_eq!(
        activation.trace().relations().last(),
        Some(&WorkspaceRelationRef::Artifact(
            indexed_candidate.relation().clone()
        ))
    );
    assert_eq!(
        activation
            .trace()
            .relations()
            .iter()
            .map(|relation| relation.schema().as_str())
            .collect::<Vec<_>>(),
        vec![
            FunctionOwnsCallSite::ID,
            CallSiteHasOccurrence::ID,
            CallOccurrenceHasMarkerClaimCandidate::ID,
        ]
    );
}

impl RootProgramTraversalPolicy for ObservingFollowPolicy {
    type Error = Infallible;
    type Boundary = &'static str;

    fn decide_call(
        &mut self,
        context: &CallPolicyContext<'_>,
    ) -> Result<CallTraversalDecision<Self::Boundary>, Self::Error> {
        self.call_marker_counts.push((
            context.inherited_marker_claims.len(),
            context.attached_marker_candidates.len(),
            context.active_marker_claims.len(),
        ));
        Ok(CallTraversalDecision::Follow(
            context
                .targets
                .iter()
                .find(|target| target.role == CallTargetRole::Runtime)
                .expect("test call has a runtime target")
                .selection(),
        ))
    }

    fn decide_body(
        &mut self,
        context: &BodyPolicyContext<'_>,
    ) -> Result<BodyTraversalDecision<Self::Boundary>, Self::Error> {
        self.body_marker_counts.push((
            context.active_marker_claims.len(),
            context.endpoint_marker_candidates.len(),
        ));
        Ok(BodyTraversalDecision::Expand)
    }

    fn defining_markers(
        &mut self,
        _context: &DefiningMarkerPolicyContext<'_>,
    ) -> Result<DefiningMarkerDecision, Self::Error> {
        Ok(DefiningMarkerDecision::RejectCompleteSet)
    }
}

struct InvalidSelectionPolicy {
    target: ScopedEntityId<CallableEntity>,
}

struct ReconciliationMarkerPolicy {
    decision: DefiningMarkerDecision,
    defining_calls: usize,
    candidate_marker_counts: Vec<Vec<usize>>,
    call_active_marker_counts: Vec<usize>,
    resolutions: Vec<ProgramCallResolution>,
}

impl ReconciliationMarkerPolicy {
    fn new(decision: DefiningMarkerDecision) -> Self {
        Self {
            decision,
            defining_calls: 0,
            candidate_marker_counts: Vec::new(),
            call_active_marker_counts: Vec::new(),
            resolutions: Vec::new(),
        }
    }
}

impl RootProgramTraversalPolicy for ReconciliationMarkerPolicy {
    type Error = Infallible;
    type Boundary = &'static str;

    fn decide_call(
        &mut self,
        context: &CallPolicyContext<'_>,
    ) -> Result<CallTraversalDecision<Self::Boundary>, Self::Error> {
        self.call_active_marker_counts
            .push(context.active_marker_claims.len());
        self.resolutions.push(context.resolution.clone());
        Ok(CallTraversalDecision::Ignore)
    }

    fn decide_body(
        &mut self,
        _context: &BodyPolicyContext<'_>,
    ) -> Result<BodyTraversalDecision<Self::Boundary>, Self::Error> {
        Ok(BodyTraversalDecision::Expand)
    }

    fn defining_markers(
        &mut self,
        context: &DefiningMarkerPolicyContext<'_>,
    ) -> Result<DefiningMarkerDecision, Self::Error> {
        self.defining_calls += 1;
        self.candidate_marker_counts.push(
            context
                .candidates
                .iter()
                .map(|candidate| candidate.marker_claims.len())
                .collect(),
        );
        Ok(self.decision)
    }
}

#[derive(Debug, Eq, PartialEq)]
struct ObservedReconciliationAuthorities {
    resolution: ProgramCallResolution,
    raw: Option<ReconciledCallTargetAuthority>,
    raw_role: Option<CallTargetRole>,
    defining_source: Option<ReconciledCallTargetAuthority>,
    effective_source: Option<ReconciledCallTargetAuthority>,
    defining_target: Option<ReconciledCallTargetAuthority>,
    metadata: Vec<ReconciledCallTargetAuthority>,
    contract: Vec<ReconciledCallTargetAuthority>,
    candidates: usize,
}

#[derive(Default)]
struct ReconciliationAuthorityPolicy {
    follow_defining_target: bool,
    observed: Vec<ObservedReconciliationAuthorities>,
}

impl RootProgramTraversalPolicy for ReconciliationAuthorityPolicy {
    type Error = Infallible;
    type Boundary = &'static str;

    fn decide_call(
        &mut self,
        context: &CallPolicyContext<'_>,
    ) -> Result<CallTraversalDecision<Self::Boundary>, Self::Error> {
        let reconciliation = context
            .reconciliation
            .as_ref()
            .expect("authority fixture has a reconciliation context");
        self.observed.push(ObservedReconciliationAuthorities {
            resolution: context.resolution.clone(),
            raw: reconciliation.raw_target.map(|target| target.authority),
            raw_role: reconciliation.raw_target.map(|target| target.role),
            defining_source: reconciliation
                .defining_source_target
                .map(|target| target.authority),
            effective_source: reconciliation
                .effective_source_target
                .map(|target| target.authority),
            defining_target: reconciliation
                .defining_target
                .map(|target| target.authority),
            metadata: reconciliation
                .effective_metadata_targets
                .iter()
                .map(|target| target.authority)
                .collect(),
            contract: reconciliation
                .contract_targets
                .iter()
                .map(|target| target.authority)
                .collect(),
            candidates: reconciliation.candidates.len(),
        });
        Ok(if self.follow_defining_target {
            CallTraversalDecision::Follow(
                reconciliation
                    .defining_target
                    .expect("fixture has defining-target consensus")
                    .selection(),
            )
        } else {
            CallTraversalDecision::Ignore
        })
    }

    fn decide_body(
        &mut self,
        _context: &BodyPolicyContext<'_>,
    ) -> Result<BodyTraversalDecision<Self::Boundary>, Self::Error> {
        Ok(BodyTraversalDecision::Expand)
    }

    fn defining_markers(
        &mut self,
        _context: &DefiningMarkerPolicyContext<'_>,
    ) -> Result<DefiningMarkerDecision, Self::Error> {
        Ok(DefiningMarkerDecision::RejectCompleteSet)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservedCallPolicyInput {
    occurrence: CallOccurrenceKey,
    effective_kind: CallKind,
    resolution: ProgramCallResolution,
    targets: Vec<(CallTargetRole, FunctionKey, ArtifactScopeId)>,
    marker_counts: (usize, usize, usize),
}

#[derive(Default)]
struct RecordingCallPolicy {
    calls: Vec<ObservedCallPolicyInput>,
}

impl RootProgramTraversalPolicy for RecordingCallPolicy {
    type Error = Infallible;
    type Boundary = &'static str;

    fn decide_call(
        &mut self,
        context: &CallPolicyContext<'_>,
    ) -> Result<CallTraversalDecision<Self::Boundary>, Self::Error> {
        self.calls.push(ObservedCallPolicyInput {
            occurrence: *context.occurrence.data().key(),
            effective_kind: context.effective_kind,
            resolution: context.resolution.clone(),
            targets: context
                .targets
                .iter()
                .map(|target| {
                    (
                        target.role,
                        *target.callable.data().key(),
                        target.callable.reference().scope().clone(),
                    )
                })
                .collect(),
            marker_counts: (
                context.inherited_marker_claims.len(),
                context.attached_marker_candidates.len(),
                context.active_marker_claims.len(),
            ),
        });
        Ok(CallTraversalDecision::Ignore)
    }

    fn decide_body(
        &mut self,
        _context: &BodyPolicyContext<'_>,
    ) -> Result<BodyTraversalDecision<Self::Boundary>, Self::Error> {
        Ok(BodyTraversalDecision::Expand)
    }

    fn defining_markers(
        &mut self,
        _context: &DefiningMarkerPolicyContext<'_>,
    ) -> Result<DefiningMarkerDecision, Self::Error> {
        Ok(DefiningMarkerDecision::RejectCompleteSet)
    }
}

struct ReachBridgeThenRecordPolicy {
    bridge: CallOccurrenceKey,
    recorded: RecordingCallPolicy,
}

impl RootProgramTraversalPolicy for ReachBridgeThenRecordPolicy {
    type Error = Infallible;
    type Boundary = &'static str;

    fn decide_call(
        &mut self,
        context: &CallPolicyContext<'_>,
    ) -> Result<CallTraversalDecision<Self::Boundary>, Self::Error> {
        if context.occurrence.data().key() == &self.bridge {
            return Ok(CallTraversalDecision::Follow(
                context
                    .targets
                    .iter()
                    .find(|target| target.role == CallTargetRole::Runtime)
                    .expect("bridge has one runtime target")
                    .selection(),
            ));
        }
        self.recorded.decide_call(context)
    }

    fn decide_body(
        &mut self,
        context: &BodyPolicyContext<'_>,
    ) -> Result<BodyTraversalDecision<Self::Boundary>, Self::Error> {
        self.recorded.decide_body(context)
    }

    fn defining_markers(
        &mut self,
        context: &DefiningMarkerPolicyContext<'_>,
    ) -> Result<DefiningMarkerDecision, Self::Error> {
        self.recorded.defining_markers(context)
    }
}

#[derive(Default)]
struct FollowEveryRuntimePolicy {
    calls: Vec<CallOccurrenceKey>,
}

impl RootProgramTraversalPolicy for FollowEveryRuntimePolicy {
    type Error = Infallible;
    type Boundary = &'static str;

    fn decide_call(
        &mut self,
        context: &CallPolicyContext<'_>,
    ) -> Result<CallTraversalDecision<Self::Boundary>, Self::Error> {
        self.calls.push(*context.occurrence.data().key());
        Ok(CallTraversalDecision::Follow(
            context
                .targets
                .iter()
                .find(|target| target.role == CallTargetRole::Runtime)
                .expect("each raw and synthetic fixture call has one runtime target")
                .selection(),
        ))
    }

    fn decide_body(
        &mut self,
        _context: &BodyPolicyContext<'_>,
    ) -> Result<BodyTraversalDecision<Self::Boundary>, Self::Error> {
        Ok(BodyTraversalDecision::Expand)
    }

    fn defining_markers(
        &mut self,
        _context: &DefiningMarkerPolicyContext<'_>,
    ) -> Result<DefiningMarkerDecision, Self::Error> {
        Ok(DefiningMarkerDecision::RejectCompleteSet)
    }
}

impl RootProgramTraversalPolicy for InvalidSelectionPolicy {
    type Error = Infallible;
    type Boundary = &'static str;

    fn decide_call(
        &mut self,
        context: &CallPolicyContext<'_>,
    ) -> Result<CallTraversalDecision<Self::Boundary>, Self::Error> {
        Ok(CallTraversalDecision::Follow(CallTargetSelection {
            role: context.targets[0].role,
            callable: self.target.clone(),
            authority: ReconciledCallTargetAuthority::ConsumerRaw,
        }))
    }

    fn decide_body(
        &mut self,
        _context: &BodyPolicyContext<'_>,
    ) -> Result<BodyTraversalDecision<Self::Boundary>, Self::Error> {
        Ok(BodyTraversalDecision::Expand)
    }

    fn defining_markers(
        &mut self,
        _context: &DefiningMarkerPolicyContext<'_>,
    ) -> Result<DefiningMarkerDecision, Self::Error> {
        Ok(DefiningMarkerDecision::RejectCompleteSet)
    }
}

#[test]
fn exact_root_prepares_emits_and_resolves_an_explicit_empty_path() {
    let registry = registry();
    let scope = ArtifactScopeId::for_in_memory(1, 0);
    let root_key = FunctionKey::new(definition(1, 7), Some(instance(9)));
    let artifact = root_artifact(
        &registry,
        &[(root_key, FunctionBodyProvenance::DefiningArtifact)],
    );
    let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
    let workspace = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
    let index =
        WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 1)])
            .unwrap();
    let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
    let request = RootProgramTraversalRequest::new(
        DomainId::new("sniff-test.test.root").unwrap(),
        scope,
        root_key,
        CallAttributionRole::CallSite,
        MarkerProbe::SourceCallsite,
        8,
    );

    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request,
        &mut ExpandPolicy,
    )
    .unwrap();
    assert_eq!(prepared.composition_edge_count(), 0);
    assert_eq!(prepared.body_visits.len(), 1);

    let mut builder = CompositionRelationBuilder::new(
        prepared.root(),
        &workspace,
        registry.composition_relations(),
    )
    .unwrap();
    let emitted = prepared.emit(&mut builder).unwrap();
    let composition = builder.finalize().unwrap();
    let graph = WorkspaceRelationGraph::new(emitted.root(), &workspace, &composition).unwrap();
    let resolved = emitted
        .resolve(&graph, registry.composition_relations())
        .unwrap();

    assert_eq!(resolved.body_visits().len(), 1);
    assert_eq!(resolved.body_visits()[0].function(), root_key);
    assert!(resolved.body_visits()[0].trace().relations().is_empty());
    assert_eq!(
        resolved.body_visits()[0].trace().root(),
        resolved.body_visits()[0].trace().target()
    );
}

#[test]
fn expanded_body_visits_every_owned_effect_in_canonical_site_order() {
    let registry = registry();
    let scope = ArtifactScopeId::for_in_memory(1, 1);
    let root = FunctionKey::new(definition(1, 8), Some(instance(10)));
    let artifact = direct_effect_artifact(&registry, root, &[(7, 3), (1, 9), (1, 2)]);
    let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
    let workspace = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
    let index =
        WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 1)])
            .unwrap();
    let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request("sniff-test.test.effect-order", scope, root),
        &mut ExpandPolicy,
    )
    .unwrap();
    let traversal = resolve_prepared(prepared, &workspace, &registry);

    assert_eq!(traversal.body_visits()[0].order(), 0);
    assert_eq!(
        traversal
            .effect_visits()
            .iter()
            .map(|visit| {
                (
                    visit.data().site().basic_block(),
                    visit.data().site().statement_index(),
                    visit.order(),
                )
            })
            .collect::<Vec<_>>(),
        vec![(1, 2, 1), (1, 9, 2), (7, 3, 3)]
    );
    assert!(traversal.occurrence_visits().is_empty());
}

#[test]
fn direct_effect_retains_exact_ownership_route_and_empty_optional_context() {
    let registry = registry();
    let scope = ArtifactScopeId::for_in_memory(1, 2);
    let root = FunctionKey::new(definition(1, 9), Some(instance(11)));
    let artifact = direct_effect_artifact(&registry, root, &[(2, 4)]);
    let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
    let workspace = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
    let index =
        WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 1)])
            .unwrap();
    let [indexed] = index.effect_site_edges_owned_by(&scope, &root).unwrap() else {
        panic!("fixture has exactly one indexed effect")
    };
    let ownership = indexed.relation().clone();
    let effect_id = indexed.effect().clone();
    let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request("sniff-test.test.direct-effect", scope, root),
        &mut ExpandPolicy,
    )
    .unwrap();
    let traversal = resolve_prepared(prepared, &workspace, &registry);
    let [visit] = traversal.effect_visits() else {
        panic!("the direct effect is visited once")
    };

    assert_eq!(visit.effect(), &effect_id);
    assert_eq!(visit.site(), indexed.site());
    assert!(visit.source_anchors().is_empty());
    assert!(visit.macro_frames().is_empty());
    assert!(visit.inherited_markers().is_empty());
    assert!(visit.attached_marker_candidates().is_empty());
    assert!(visit.active_markers().is_empty());
    assert_eq!(
        visit.trace().relations(),
        &[WorkspaceRelationRef::Artifact(ownership)]
    );
}

#[test]
fn direct_unsafe_operation_retains_exact_typed_context_and_ownership_route() {
    let registry = registry();
    let scope = ArtifactScopeId::for_in_memory(1, 20);
    let root = FunctionKey::new(definition(1, 20), Some(instance(20)));
    let mut fixture = ConfiguredCallArtifactBuilder::new(&registry, root);
    let operation = fixture.insert_unsafe_operation(root, 0, SafetyOperationKind::DerefRawPointer);
    let artifact = fixture.finish(&registry);
    let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
    let workspace = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
    let index =
        WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 1)])
            .unwrap();
    let [indexed] = index
        .unsafe_operation_edges_owned_by(&scope, &root)
        .unwrap()
    else {
        panic!("fixture has exactly one indexed unsafe operation")
    };
    let group = index
        .unsafe_operation_group_edge(&scope, operation.key())
        .unwrap()
        .clone();
    let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request(
            "sniff-test.test.direct-unsafe-operation",
            scope.clone(),
            root,
        ),
        &mut ExpandPolicy,
    )
    .unwrap();
    let traversal = resolve_prepared(prepared, &workspace, &registry);
    let [visit] = traversal.unsafe_operation_visits() else {
        panic!("the direct unsafe operation is visited once")
    };

    assert_eq!(visit.operation(), indexed.operation_id());
    assert_eq!(visit.key(), indexed.operation());
    assert_eq!(
        visit.data(),
        index
            .exact_unsafe_operation(&scope, operation.key())
            .unwrap()
            .data()
    );
    assert_eq!(visit.owner(), traversal.body_visits()[0].body());
    assert_eq!(visit.owner_data(), traversal.body_visits()[0].data());
    assert_eq!(visit.owner_relation(), indexed.relation());
    assert_eq!(visit.safety_group(), &group.group().id());
    assert_eq!(visit.safety_group_data(), group.group().data());
    assert_eq!(visit.safety_group_relation(), group.relation());
    assert!(visit.source_anchors().is_empty());
    assert!(visit.macro_frames().is_empty());
    assert!(visit.inherited_markers().is_empty());
    assert!(visit.attached_marker_candidates().is_empty());
    assert!(visit.active_markers().is_empty());
    assert_eq!(
        visit.trace().relations(),
        &[WorkspaceRelationRef::Artifact(indexed.relation().clone())]
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one hostile test verifies the complete exact unsafe macro output bundle"
)]
fn macro_unsafe_operation_retains_exact_route_sources_callsites_and_markers() {
    let registry = registry();
    let scope = ArtifactScopeId::for_in_memory(1, 21);
    let root = FunctionKey::new(definition(1, 21), Some(instance(21)));
    let domain = "sniff-test.test.macro-unsafe-operation";
    let mut fixture = ConfiguredCallArtifactBuilder::new(&registry, root);
    let operation = fixture.insert_unsafe_operation(root, 0, SafetyOperationKind::InlineAssembly);
    let (presentation_key, presentation) = fixture.insert_anchor();
    let (expanded_key, expanded) = fixture.insert_anchor();
    fixture.attach_unsafe_operation_source_anchor(
        &operation,
        UnsafeOperationSourceAnchorRole::Expanded,
        &expanded,
    );
    fixture.attach_unsafe_operation_source_anchor(
        &operation,
        UnsafeOperationSourceAnchorRole::Presentation,
        &presentation,
    );
    fixture.insert_unsafe_operation_macro_route(&operation, &[Some(presentation.clone()), None]);
    let claim =
        fixture.attach_unsafe_operation_marker(&operation, domain, MarkerMatch::SourceCallsite);
    let artifact = fixture.finish(&registry);
    let workspace = WorkspaceFactView::compose([(
        scope.clone(),
        ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
    )])
    .unwrap();
    let index =
        WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 1)])
            .unwrap();
    let indexed_path = index
        .unsafe_operation_macro_path(&scope, operation.key())
        .unwrap()
        .unwrap()
        .clone();
    let ownership = index
        .unsafe_operation_edges_owned_by(&scope, &root)
        .unwrap()[0]
        .relation()
        .clone();
    let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request(domain, scope.clone(), root),
        &mut ExpandPolicy,
    )
    .unwrap();
    let traversal = resolve_prepared(prepared, &workspace, &registry);
    let [visit] = traversal.unsafe_operation_visits() else {
        panic!("macro operation is visited once")
    };

    assert_eq!(
        visit
            .source_anchors()
            .iter()
            .map(ResolvedUnsafeOperationSourceAnchor::role)
            .collect::<Vec<_>>(),
        vec![
            UnsafeOperationSourceAnchorRole::Presentation,
            UnsafeOperationSourceAnchorRole::Expanded,
        ]
    );
    assert_eq!(visit.source_anchors()[0].key(), &presentation_key);
    assert_eq!(visit.source_anchors()[1].key(), &expanded_key);
    assert_eq!(visit.macro_frames().len(), 2);
    for (resolved, indexed) in visit.macro_frames().iter().zip(indexed_path.frames()) {
        assert_eq!(resolved.frame(), &indexed.id());
        assert_eq!(resolved.data(), indexed.data());
    }
    let callsite = visit.macro_frames()[0].callsite().unwrap();
    assert_eq!(callsite.key(), &presentation_key);
    assert_eq!(
        callsite.anchor(),
        indexed_path.callsites()[0].as_ref().unwrap().anchor()
    );
    assert_eq!(
        callsite.relation(),
        indexed_path.callsites()[0].as_ref().unwrap().relation()
    );
    assert!(visit.macro_frames()[1].callsite().is_none());
    assert!(visit.inherited_markers().is_empty());
    assert_eq!(
        visit.attached_marker_candidates()[0].claim(),
        &index.exact_marker_claim(&scope, claim.key()).unwrap().id()
    );
    assert_eq!(visit.active_markers(), visit.attached_marker_candidates());
    assert_eq!(visit.owner_relation(), &ownership);
    let expected = std::iter::once(indexed_path.entry().clone())
        .chain(indexed_path.links().iter().cloned())
        .chain(std::iter::once(indexed_path.exit().clone()))
        .map(WorkspaceRelationRef::Artifact)
        .collect::<Vec<_>>();
    assert_eq!(visit.trace().relations(), expected);
    assert!(
        !visit
            .trace()
            .relations()
            .contains(&WorkspaceRelationRef::Artifact(ownership))
    );
}

#[test]
fn unsafe_operations_use_local_id_order_and_do_not_leak_attached_markers_to_siblings() {
    let registry = registry();
    let scope = ArtifactScopeId::for_in_memory(1, 22);
    let root = FunctionKey::new(definition(1, 22), Some(instance(22)));
    let domain = "sniff-test.test.unsafe-operation-order";
    let mut fixture = ConfiguredCallArtifactBuilder::new(&registry, root);
    fixture.insert_unsafe_operation(root, 1, SafetyOperationKind::InlineAssembly);
    let first = fixture.insert_unsafe_operation(root, 0, SafetyOperationKind::DerefRawPointer);
    fixture.attach_unsafe_operation_marker(&first, domain, MarkerMatch::SourceCallsite);
    let artifact = fixture.finish(&registry);
    let workspace = WorkspaceFactView::compose([(
        scope.clone(),
        ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
    )])
    .unwrap();
    let index =
        WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 1)])
            .unwrap();
    let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
    let traversal = resolve_prepared(
        PreparedRootProgramTraversal::prepare(
            &workspace,
            &index,
            &authority,
            &request(domain, scope, root),
            &mut ExpandPolicy,
        )
        .unwrap(),
        &workspace,
        &registry,
    );
    let [first, sibling] = traversal.unsafe_operation_visits() else {
        panic!("both operations are visited")
    };
    assert_eq!([first.key().local_id(), sibling.key().local_id()], [0, 1]);
    assert_eq!(first.attached_marker_candidates().len(), 1);
    assert_eq!(first.active_markers().len(), 1);
    assert!(sibling.inherited_markers().is_empty());
    assert!(sibling.attached_marker_candidates().is_empty());
    assert!(sibling.active_markers().is_empty());
}

#[test]
fn resolved_traversal_rejects_a_same_coordinate_replacement_workspace_brand() {
    let registry = registry();
    let scope = ArtifactScopeId::for_in_memory(1, 5);
    let root = FunctionKey::new(definition(1, 13), Some(instance(15)));
    let mut fixture = ConfiguredCallArtifactBuilder::new(&registry, root);
    fixture.insert_effect(root, 0, 0);
    fixture.insert_unsafe_operation(root, 0, SafetyOperationKind::DerefRawPointer);
    let artifact = fixture.finish(&registry);
    let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
    let workspace = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
    let index =
        WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 1)])
            .unwrap();
    let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request("sniff-test.test.traversal-brand", scope.clone(), root),
        &mut ExpandPolicy,
    )
    .unwrap();
    let traversal = resolve_prepared(prepared, &workspace, &registry);
    assert!(traversal.belongs_to(&workspace));

    let replacement_view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
    let replacement = WorkspaceFactView::compose([(scope, replacement_view)]).unwrap();
    assert!(!traversal.belongs_to(&replacement));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one hostile test verifies the complete exact macro-effect output bundle"
)]
fn macro_effect_retains_exact_route_sources_and_depth_aligned_callsites() {
    let registry = registry();
    let scope = ArtifactScopeId::for_in_memory(1, 3);
    let root = FunctionKey::new(definition(1, 10), Some(instance(12)));
    let mut fixture = ConfiguredCallArtifactBuilder::new(&registry, root);
    let effect = fixture.insert_effect(root, 3, 5);
    let (presentation_key, presentation) = fixture.insert_anchor();
    let (expanded_key, expanded) = fixture.insert_anchor();
    fixture.attach_effect_source_anchor(&effect, EffectSourceAnchorRole::Expanded, &expanded);
    fixture.attach_effect_source_anchor(
        &effect,
        EffectSourceAnchorRole::Presentation,
        &presentation,
    );
    fixture.insert_effect_macro_route(&effect, &[Some(presentation.clone()), None]);
    let artifact = fixture.finish(&registry);
    let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
    let workspace = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
    let index =
        WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 1)])
            .unwrap();
    let effect_key = *effect.key();
    let indexed_anchors = index
        .effect_source_anchors(&scope, &effect_key)
        .unwrap()
        .to_vec();
    let indexed_path = index
        .effect_macro_path(&scope, &effect_key)
        .unwrap()
        .expect("effect has an exact macro path")
        .clone();
    let ownership = index.effect_site_edges_owned_by(&scope, &root).unwrap()[0]
        .relation()
        .clone();
    let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request("sniff-test.test.macro-effect", scope, root),
        &mut ExpandPolicy,
    )
    .unwrap();
    let traversal = resolve_prepared(prepared, &workspace, &registry);
    let [visit] = traversal.effect_visits() else {
        panic!("the macro-produced effect is visited once")
    };

    assert_eq!(
        visit
            .source_anchors()
            .iter()
            .map(ResolvedEffectSourceAnchor::role)
            .collect::<Vec<_>>(),
        vec![
            EffectSourceAnchorRole::Presentation,
            EffectSourceAnchorRole::Expanded,
        ]
    );
    assert_eq!(visit.source_anchors()[0].key(), &presentation_key);
    assert_eq!(visit.source_anchors()[1].key(), &expanded_key);
    for (resolved, indexed) in visit.source_anchors().iter().zip(&indexed_anchors) {
        assert_eq!(resolved.key(), indexed.anchor_key());
        assert_eq!(resolved.anchor(), indexed.anchor());
        assert_eq!(resolved.relation(), indexed.relation());
    }

    assert_eq!(visit.macro_frames().len(), 2);
    for (resolved, indexed) in visit.macro_frames().iter().zip(indexed_path.frames()) {
        assert_eq!(resolved.frame(), &indexed.id());
        assert_eq!(resolved.data(), indexed.data());
    }
    let first_callsite = visit.macro_frames()[0]
        .callsite()
        .expect("outer frame retains its callsite");
    let indexed_callsite = indexed_path.callsites()[0]
        .as_ref()
        .expect("indexed outer frame has its callsite");
    assert_eq!(first_callsite.key(), indexed_callsite.anchor_key());
    assert_eq!(first_callsite.anchor(), indexed_callsite.anchor());
    assert_eq!(first_callsite.relation(), indexed_callsite.relation());
    assert!(visit.macro_frames()[1].callsite().is_none());
    assert!(indexed_path.callsites()[1].is_none());

    let expected_relations = std::iter::once(indexed_path.entry().clone())
        .chain(indexed_path.links().iter().cloned())
        .chain(std::iter::once(indexed_path.exit().clone()))
        .map(WorkspaceRelationRef::Artifact)
        .collect::<Vec<_>>();
    assert_eq!(visit.trace().relations(), expected_relations);
    assert!(
        !visit
            .trace()
            .relations()
            .contains(&WorkspaceRelationRef::Artifact(ownership))
    );
    assert_eq!(
        visit
            .trace()
            .relations()
            .iter()
            .map(|relation| relation.schema().as_str())
            .collect::<Vec<_>>(),
        vec![
            FunctionEntersMacroExpansion::ID,
            MacroExpansionEntersMacroExpansion::ID,
            MacroExpansionProducesEffectSite::ID,
        ]
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one scenario verifies marker isolation and the interleaved global event order"
)]
fn effect_markers_filter_exactly_and_never_leak_to_siblings_calls_or_visit_keys() {
    let registry = registry();
    let scope = ArtifactScopeId::for_in_memory(1, 4);
    let root = FunctionKey::new(definition(1, 11), Some(instance(13)));
    let target = FunctionKey::new(definition(1, 12), Some(instance(14)));
    let domain = "sniff-test.test.effect-markers";
    let mut fixture = ConfiguredCallArtifactBuilder::new(&registry, root);
    let target_callable = fixture
        .insert_target(target, TargetFixture::SeparateWithBody)
        .unwrap();
    let root_occurrence = fixture.insert_call_for(root, 0, Some(&target_callable));
    fixture.insert_marker(
        MarkerEndpoint::Call,
        domain,
        MarkerMatch::SourceCallsite,
        Some(&root_occurrence),
    );
    let marked_effect = fixture.insert_effect(target, 1, 0);
    fixture.attach_effect_marker(&marked_effect, domain, MarkerMatch::SourceCallsite);
    fixture.attach_effect_marker(
        &marked_effect,
        "sniff-test.test.other-domain",
        MarkerMatch::SourceCallsite,
    );
    fixture.attach_effect_marker(&marked_effect, domain, MarkerMatch::MacroDefinitionFirst);
    fixture.insert_effect(target, 2, 0);
    fixture.insert_call_for(target, 0, Some(&target_callable));
    let artifact = fixture.finish(&registry);
    let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
    let workspace = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
    let index =
        WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 1)])
            .unwrap();
    let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request(domain, scope, root),
        &mut FollowWhenTargetPolicy,
    )
    .unwrap();
    let traversal = resolve_prepared(prepared, &workspace, &registry);

    assert_eq!(
        traversal
            .body_visits()
            .iter()
            .map(ResolvedBodyVisit::order)
            .collect::<Vec<_>>(),
        vec![0, 3]
    );
    assert_eq!(
        traversal
            .occurrence_visits()
            .iter()
            .map(ResolvedOccurrenceVisit::order)
            .collect::<Vec<_>>(),
        vec![1, 6]
    );
    assert_eq!(
        traversal
            .effect_visits()
            .iter()
            .map(ResolvedEffectVisit::order)
            .collect::<Vec<_>>(),
        vec![4, 5],
        "each expanded body is visited before all canonical effects, then its calls"
    );
    assert_eq!(
        traversal
            .followed_calls()
            .iter()
            .map(ResolvedFollowedCall::order)
            .collect::<Vec<_>>(),
        vec![2, 7]
    );
    let [marked, sibling] = traversal.effect_visits() else {
        panic!("target body has exactly two effect visits")
    };
    assert_eq!(marked.inherited_markers().len(), 1);
    assert_eq!(marked.attached_marker_candidates().len(), 1);
    assert_eq!(marked.active_markers().len(), 2);
    assert_eq!(
        marked.attached_marker_candidates()[0]
            .trace()
            .relations()
            .last()
            .map(|relation| relation.schema().as_str()),
        Some(EffectSiteHasMarkerClaimCandidate::ID)
    );
    assert_eq!(sibling.inherited_markers().len(), 1);
    assert!(sibling.attached_marker_candidates().is_empty());
    assert_eq!(sibling.active_markers().len(), 1);
    let target_call = &traversal.occurrence_visits()[1];
    assert_eq!(target_call.inherited_markers().len(), 1);
    assert!(target_call.attached_marker_candidates().is_empty());
    assert_eq!(target_call.active_markers().len(), 1);
    assert_eq!(traversal.body_visits().len(), 2);
    assert_eq!(traversal.effect_visits().len(), 2);
    assert!(
        traversal
            .outcomes()
            .iter()
            .any(|outcome| outcome.kind() == &TraversalOutcomeKind::Cycle)
    );
}

#[test]
fn exact_root_request_falls_back_only_to_same_scope_generic_body() {
    let registry = registry();
    let scope = ArtifactScopeId::for_in_memory(2, 0);
    let generic = FunctionKey::new(definition(2, 3), None);
    let requested = FunctionKey::new(generic.definition(), Some(instance(4)));
    let artifact = root_artifact(
        &registry,
        &[(generic, FunctionBodyProvenance::DefiningArtifact)],
    );
    let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
    let workspace = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
    let index =
        WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 2)])
            .unwrap();
    let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
    let request = RootProgramTraversalRequest::new(
        DomainId::new("sniff-test.test.generic-root").unwrap(),
        scope,
        requested,
        CallAttributionRole::CallSite,
        MarkerProbe::SourceCallsite,
        8,
    );

    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request,
        &mut ExpandPolicy,
    )
    .unwrap();

    assert_eq!(prepared.body_visits.len(), 1);
    assert_eq!(*prepared.body_visits[0].data.key(), generic);
    assert_eq!(prepared.root.entity, prepared.body_visits[0].body.erase());
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one direct route verifies every exact followed-call identity and trace field"
)]
fn direct_call_uses_exact_artifact_edges_then_one_typed_body_selection_edge() {
    let registry = registry();
    let scope = ArtifactScopeId::for_in_memory(3, 0);
    let root = FunctionKey::new(definition(3, 1), Some(instance(1)));
    let target = FunctionKey::new(definition(3, 2), Some(instance(2)));
    let artifact = direct_call_artifact(&registry, root, target);
    let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
    let workspace = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
    let index =
        WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 3)])
            .unwrap();
    let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
    let request = RootProgramTraversalRequest::new(
        DomainId::new("sniff-test.test.direct-call").unwrap(),
        scope.clone(),
        root,
        CallAttributionRole::CallSite,
        MarkerProbe::SourceCallsite,
        8,
    );
    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request,
        &mut FollowRuntimePolicy,
    )
    .unwrap();
    assert_eq!(prepared.composition_edge_count(), 1);

    let mut builder = CompositionRelationBuilder::new(
        prepared.root(),
        &workspace,
        registry.composition_relations(),
    )
    .unwrap();
    let emitted = prepared.emit(&mut builder).unwrap();
    let composition = builder.finalize().unwrap();
    let graph = WorkspaceRelationGraph::new(emitted.root(), &workspace, &composition).unwrap();
    let resolved = emitted
        .resolve(&graph, registry.composition_relations())
        .unwrap();

    assert_eq!(resolved.body_visits().len(), 2);
    assert_eq!(resolved.occurrence_visits().len(), 1);
    assert!(resolved.occurrence_visits()[0].macro_frames().is_empty());
    let [followed] = resolved.followed_calls() else {
        panic!("the direct runtime target must retain one followed call");
    };
    let occurrence = index
        .exact_call_occurrence(&scope, &CallOccurrenceKey::new(root, 0))
        .unwrap();
    let call_site = index
        .exact_call_site(&scope, &CallSiteKey::new(root, 0))
        .unwrap();
    let safety_group = index
        .exact_safety_group(&scope, &SafetyEffectGroupKey::new(root, 0))
        .unwrap();
    let target_callable = index.exact_callable(&scope, &target).unwrap();
    assert_eq!(followed.occurrence(), &occurrence.id());
    assert_eq!(followed.occurrence_data(), occurrence.data());
    assert_eq!(followed.call_site(), &call_site.id());
    assert_eq!(followed.call_site_data(), call_site.data());
    assert_eq!(followed.safety_group(), &safety_group.id());
    assert_eq!(followed.safety_group_data(), safety_group.data());
    assert_eq!(followed.kind(), CallKind::DirectCall);
    assert_eq!(followed.effective_kind(), CallKind::DirectCall);
    assert_eq!(followed.resolution(), &ProgramCallResolution::Persisted);
    assert_eq!(followed.target().role(), CallTargetRole::Runtime);
    assert_eq!(
        followed.target().authority(),
        ReconciledCallTargetAuthority::ConsumerRaw
    );
    assert_eq!(followed.target().callable(), &target_callable.id());
    assert_eq!(followed.target_data(), target_callable.data());
    assert!(followed.source_anchors().is_empty());
    assert!(followed.macro_frames().is_empty());
    assert!(followed.inherited_markers().is_empty());
    assert!(followed.attached_marker_candidates().is_empty());
    assert!(followed.active_markers().is_empty());
    assert_eq!(followed.trace().target(), &target_callable.id().erase());
    assert!(
        resolved.occurrence_visits()[0].order() < followed.order()
            && followed.order() < resolved.body_visits()[1].order()
    );
    assert_eq!(resolved.body_visits()[1].function(), target);
    let schemas = resolved.body_visits()[1]
        .trace()
        .relations()
        .iter()
        .map(|relation| match relation {
            WorkspaceRelationRef::Artifact(reference) => reference.relation().schema.as_str(),
            WorkspaceRelationRef::Composition(reference) => reference.schema.as_str(),
        })
        .collect::<Vec<_>>();
    assert_eq!(
        schemas,
        vec![
            FunctionOwnsCallSite::ID,
            CallSiteHasOccurrence::ID,
            CallOccurrenceTargetsCallable::ID,
            CallableSelectsFunctionBody::ID,
        ]
    );
    assert_eq!(
        followed
            .trace()
            .relations()
            .iter()
            .map(|relation| relation.schema().as_str())
            .collect::<Vec<_>>(),
        vec![
            FunctionOwnsCallSite::ID,
            CallSiteHasOccurrence::ID,
            CallOccurrenceTargetsCallable::ID,
        ]
    );
}

#[test]
fn boundary_and_ignore_do_not_consume_a_zero_node_budget() {
    let registry = registry();
    let scope = ArtifactScopeId::for_in_memory(4, 0);
    let root = FunctionKey::new(definition(4, 1), Some(instance(1)));
    let mut fixture = ConfiguredCallArtifactBuilder::new(&registry, root);
    fixture.insert_effect(root, 0, 0);
    fixture.insert_unsafe_operation(root, 0, SafetyOperationKind::DerefRawPointer);
    let artifact = fixture.finish(&registry);
    let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
    let workspace = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
    let index =
        WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 4)])
            .unwrap();
    let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
    let request = RootProgramTraversalRequest::new(
        DomainId::new("sniff-test.test.zero-budget").unwrap(),
        scope,
        root,
        CallAttributionRole::CallSite,
        MarkerProbe::SourceCallsite,
        0,
    );

    let boundary = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request,
        &mut BoundaryPolicy,
    )
    .unwrap();
    assert_eq!(boundary.body_boundaries.len(), 1);
    assert!(boundary.effect_visits.is_empty());
    assert!(boundary.unsafe_operation_visits.is_empty());
    assert!(boundary.outcomes.is_empty());

    let ignored = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request,
        &mut IgnoreBodyPolicy,
    )
    .unwrap();
    assert!(ignored.body_boundaries.is_empty());
    assert!(ignored.effect_visits.is_empty());
    assert!(ignored.unsafe_operation_visits.is_empty());
    assert!(matches!(
        ignored.outcomes.as_slice(),
        [PreparedTraversalOutcome {
            kind: TraversalOutcomeKind::Ignored,
            ..
        }]
    ));
}

#[test]
fn expand_with_zero_budget_records_budget_exhaustion_without_visiting_the_root() {
    let registry = registry();
    let scope = ArtifactScopeId::for_in_memory(4, 1);
    let root = FunctionKey::new(definition(4, 2), Some(instance(2)));
    let mut fixture = ConfiguredCallArtifactBuilder::new(&registry, root);
    fixture.insert_effect(root, 0, 0);
    fixture.insert_unsafe_operation(root, 0, SafetyOperationKind::DerefRawPointer);
    let artifact = fixture.finish(&registry);
    let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
    let workspace = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
    let index =
        WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 4)])
            .unwrap();
    let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
    let request = RootProgramTraversalRequest::new(
        DomainId::new("sniff-test.test.zero-expand-budget").unwrap(),
        scope,
        root,
        CallAttributionRole::CallSite,
        MarkerProbe::SourceCallsite,
        0,
    );

    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request,
        &mut ExpandPolicy,
    )
    .unwrap();

    assert!(prepared.body_visits.is_empty());
    assert!(prepared.effect_visits.is_empty());
    assert!(prepared.unsafe_operation_visits.is_empty());
    assert!(prepared.occurrence_visits.is_empty());
    assert!(prepared.body_boundaries.is_empty());
    assert!(matches!(
        prepared.outcomes.as_slice(),
        [PreparedTraversalOutcome {
            kind: TraversalOutcomeKind::BudgetExceeded { limit: 0 },
            ..
        }]
    ));
}

#[test]
fn node_budget_is_an_exact_limit_on_expanded_bodies() {
    let registry = registry();
    let scope = ArtifactScopeId::for_in_memory(4, 2);
    let root = FunctionKey::new(definition(4, 3), Some(instance(3)));
    let target = FunctionKey::new(definition(4, 4), Some(instance(4)));
    let config = ConfiguredCall {
        kind: CallKind::DirectCall,
        attribution: vec![CallAttributionRole::CallSite],
        callable_key: None,
        target: TargetFixture::None,
        call_count: 1,
        route: CallRoute::Site,
        marker: None,
    };
    let mut fixture = ConfiguredCallArtifactBuilder::new(&registry, root);
    let target_callable = fixture
        .insert_target(target, TargetFixture::SeparateWithBody)
        .unwrap();
    fixture.insert_calls(&config, Some(&target_callable));
    fixture.insert_effect(target, 0, 0);
    let artifact = fixture.finish(&registry);
    let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
    let workspace = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
    let index =
        WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 4)])
            .unwrap();
    let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
    let request = RootProgramTraversalRequest::new(
        DomainId::new("sniff-test.test.exact-expand-budget").unwrap(),
        scope.clone(),
        root,
        CallAttributionRole::CallSite,
        MarkerProbe::SourceCallsite,
        1,
    );

    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request,
        &mut FollowRuntimePolicy,
    )
    .unwrap();

    assert_eq!(prepared.body_visits.len(), 1);
    assert_eq!(*prepared.body_visits[0].data.key(), root);
    assert!(prepared.effect_visits.is_empty());
    assert_eq!(prepared.occurrence_visits.len(), 1);
    assert_eq!(prepared.composition_edge_count(), 1);
    assert!(matches!(
        prepared.outcomes.as_slice(),
        [PreparedTraversalOutcome {
            kind: TraversalOutcomeKind::BudgetExceeded { limit: 1 },
            ..
        }]
    ));

    let target_body = index
        .exact_function(&scope, &target)
        .expect("target body exists")
        .id()
        .erase();
    let traversal = resolve_prepared(prepared, &workspace, &registry);
    let [outcome] = traversal.outcomes() else {
        panic!("the unexpanded target produces one terminal outcome");
    };
    assert_eq!(outcome.trace().target(), &target_body);
}

#[test]
fn active_self_recursion_is_a_cycle() {
    let registry = registry();
    let scope = ArtifactScopeId::for_in_memory(5, 0);
    let root = FunctionKey::new(definition(5, 1), Some(instance(1)));
    let mut fixture = ConfiguredCallArtifactBuilder::new(&registry, root);
    let recursive_target = fixture.root_callable.clone();
    fixture.insert_call_for(root, 0, Some(&recursive_target));
    fixture.insert_unsafe_operation(root, 0, SafetyOperationKind::DerefRawPointer);
    let artifact = fixture.finish(&registry);
    let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
    let workspace = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
    let index =
        WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 5)])
            .unwrap();
    let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
    let request = RootProgramTraversalRequest::new(
        DomainId::new("sniff-test.test.cycle").unwrap(),
        scope,
        root,
        CallAttributionRole::CallSite,
        MarkerProbe::SourceCallsite,
        8,
    );

    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request,
        &mut FollowRuntimePolicy,
    )
    .unwrap();

    assert_eq!(prepared.body_visits.len(), 1);
    assert_eq!(prepared.unsafe_operation_visits.len(), 1);
    assert!(
        prepared
            .outcomes
            .iter()
            .any(|outcome| outcome.kind == TraversalOutcomeKind::Cycle)
    );
}

#[test]
fn a_second_route_to_a_completed_body_is_deduplicated() {
    let registry = registry();
    let scope = ArtifactScopeId::for_in_memory(6, 0);
    let root = FunctionKey::new(definition(6, 1), Some(instance(1)));
    let target = FunctionKey::new(definition(6, 2), Some(instance(2)));
    let config = ConfiguredCall {
        kind: CallKind::DirectCall,
        attribution: vec![CallAttributionRole::CallSite],
        callable_key: None,
        target: TargetFixture::None,
        call_count: 2,
        route: CallRoute::Site,
        marker: None,
    };
    let mut fixture = ConfiguredCallArtifactBuilder::new(&registry, root);
    let target_callable = fixture
        .insert_target(target, TargetFixture::SeparateWithBody)
        .unwrap();
    fixture.insert_calls(&config, Some(&target_callable));
    fixture.insert_effect(target, 0, 0);
    fixture.insert_unsafe_operation(target, 0, SafetyOperationKind::DerefRawPointer);
    let artifact = fixture.finish(&registry);
    let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
    let workspace = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
    let index =
        WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 6)])
            .unwrap();
    let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
    let request = RootProgramTraversalRequest::new(
        DomainId::new("sniff-test.test.dedup").unwrap(),
        scope,
        root,
        CallAttributionRole::CallSite,
        MarkerProbe::SourceCallsite,
        8,
    );

    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request,
        &mut FollowRuntimePolicy,
    )
    .unwrap();

    assert_eq!(prepared.body_visits.len(), 2);
    assert_eq!(prepared.effect_visits.len(), 1);
    assert_eq!(prepared.unsafe_operation_visits.len(), 1);
    assert!(
        prepared
            .outcomes
            .iter()
            .any(|outcome| outcome.kind == TraversalOutcomeKind::Deduplicated)
    );
}

#[test]
fn multi_frame_macro_route_wins_over_the_shorter_call_site_route() {
    let registry = registry();
    let scope = ArtifactScopeId::for_in_memory(7, 0);
    let root = FunctionKey::new(definition(7, 1), Some(instance(1)));
    let target = FunctionKey::new(definition(7, 2), Some(instance(2)));
    let artifact = configured_call_artifact(
        &registry,
        root,
        target,
        &ConfiguredCall {
            kind: CallKind::DirectCall,
            attribution: vec![CallAttributionRole::CallSite],
            callable_key: None,
            target: TargetFixture::SeparateWithBody,
            call_count: 1,
            route: CallRoute::Macro,
            marker: None,
        },
    );
    let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
    let workspace = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
    let index =
        WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 7)])
            .unwrap();
    let indexed_path = index
        .call_macro_path(&scope, &CallOccurrenceKey::new(root, 0))
        .unwrap()
        .expect("call has an exact macro path")
        .clone();
    let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
    let request = RootProgramTraversalRequest::new(
        DomainId::new("sniff-test.test.macro-route").unwrap(),
        scope,
        root,
        CallAttributionRole::CallSite,
        MarkerProbe::SourceCallsite,
        8,
    );
    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request,
        &mut FollowRuntimePolicy,
    )
    .unwrap();
    let mut builder = CompositionRelationBuilder::new(
        prepared.root(),
        &workspace,
        registry.composition_relations(),
    )
    .unwrap();
    let emitted = prepared.emit(&mut builder).unwrap();
    let composition = builder.finalize().unwrap();
    let graph = WorkspaceRelationGraph::new(emitted.root(), &workspace, &composition).unwrap();
    let resolved = emitted
        .resolve(&graph, registry.composition_relations())
        .unwrap();

    let visit = &resolved.occurrence_visits()[0];
    assert_eq!(visit.macro_frames().len(), 2);
    for (resolved, indexed) in visit.macro_frames().iter().zip(indexed_path.frames()) {
        assert_eq!(resolved.frame(), &indexed.id());
        assert_eq!(resolved.data(), indexed.data());
    }
    let first_callsite = visit.macro_frames()[0]
        .callsite()
        .expect("outer frame retains its callsite");
    let indexed_callsite = indexed_path.callsites()[0]
        .as_ref()
        .expect("indexed outer frame has its callsite");
    assert_eq!(first_callsite.key(), indexed_callsite.anchor_key());
    assert_eq!(first_callsite.anchor(), indexed_callsite.anchor());
    assert_eq!(first_callsite.relation(), indexed_callsite.relation());
    assert!(visit.macro_frames()[1].callsite().is_none());
    assert!(indexed_path.callsites()[1].is_none());

    let expected_relations = std::iter::once(indexed_path.entry().clone())
        .chain(indexed_path.links().iter().cloned())
        .chain(std::iter::once(indexed_path.exit().clone()))
        .map(WorkspaceRelationRef::Artifact)
        .collect::<Vec<_>>();
    assert_eq!(visit.trace().relations(), expected_relations);
    let schemas = visit
        .trace()
        .relations()
        .iter()
        .map(|relation| match relation {
            WorkspaceRelationRef::Artifact(reference) => reference.relation().schema.as_str(),
            WorkspaceRelationRef::Composition(reference) => reference.schema.as_str(),
        })
        .collect::<Vec<_>>();
    assert_eq!(
        schemas,
        vec![
            FunctionEntersCallMacroExpansion::ID,
            CallMacroExpansionEntersCallMacroExpansion::ID,
            CallMacroExpansionProducesCallOccurrence::ID,
        ]
    );
}

#[test]
fn source_callsite_probe_activates_only_exact_domain_function_and_call_candidates() {
    let registry = registry();
    let root = FunctionKey::new(definition(8, 1), Some(instance(1)));
    let target = FunctionKey::new(definition(8, 2), Some(instance(2)));
    let domain = "sniff-test.test.marker";
    let cases = [
        (
            MarkerEndpoint::Function,
            domain,
            MarkerMatch::SourceCallsite,
            1,
        ),
        (MarkerEndpoint::Call, domain, MarkerMatch::SourceCallsite, 1),
        (
            MarkerEndpoint::Function,
            "sniff-test.test.other-domain",
            MarkerMatch::SourceCallsite,
            0,
        ),
        (
            MarkerEndpoint::Call,
            domain,
            MarkerMatch::MacroDefinitionFirst,
            0,
        ),
    ];

    for (ordinal, (endpoint, marker_domain, marker_match, expected_candidates)) in
        (0_u32..).zip(cases)
    {
        let scope = ArtifactScopeId::for_in_memory(8, ordinal);
        let artifact = configured_call_artifact(
            &registry,
            root,
            target,
            &ConfiguredCall {
                kind: CallKind::DirectCall,
                attribution: vec![CallAttributionRole::CallSite],
                callable_key: None,
                target: TargetFixture::SeparateWithBody,
                call_count: 1,
                route: CallRoute::Site,
                marker: Some((endpoint, marker_domain, marker_match)),
            },
        );
        let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
        let workspace = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
        let index =
            WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 8)])
                .unwrap();
        let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
        let request = RootProgramTraversalRequest::new(
            DomainId::new(domain).unwrap(),
            scope,
            root,
            CallAttributionRole::CallSite,
            MarkerProbe::SourceCallsite,
            8,
        );
        let prepared = PreparedRootProgramTraversal::prepare(
            &workspace,
            &index,
            &authority,
            &request,
            &mut ExpandPolicy,
        )
        .unwrap();
        let resolved = resolve_prepared(prepared, &workspace, &registry);
        let function_candidates = resolved.body_visits()[0].endpoint_marker_candidates().len();
        let call_candidates = resolved.occurrence_visits()[0]
            .attached_marker_candidates()
            .len();
        assert_eq!(
            function_candidates + call_candidates,
            expected_candidates,
            "candidate filtering differs for case {ordinal}"
        );
    }
}

#[test]
fn macro_definition_probe_activates_only_macro_definition_applicability() {
    let registry = registry();
    let root = FunctionKey::new(definition(8, 3), Some(instance(3)));
    let target = FunctionKey::new(definition(8, 4), Some(instance(4)));
    let domain = "sniff-test.test.macro-definition-marker";
    let cases = [
        (MarkerMatch::MacroDefinitionFirst, 1),
        (MarkerMatch::SourceCallsite, 0),
    ];

    for (ordinal, (marker_match, expected_candidates)) in (4_u32..).zip(cases) {
        let scope = ArtifactScopeId::for_in_memory(8, ordinal);
        let artifact = configured_call_artifact(
            &registry,
            root,
            target,
            &ConfiguredCall {
                kind: CallKind::DirectCall,
                attribution: vec![CallAttributionRole::CallSite],
                callable_key: None,
                target: TargetFixture::SeparateWithBody,
                call_count: 1,
                route: CallRoute::Macro,
                marker: Some((MarkerEndpoint::Call, domain, marker_match)),
            },
        );
        let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
        let workspace = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
        let index =
            WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 8)])
                .unwrap();
        let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
        let request = RootProgramTraversalRequest::new(
            DomainId::new(domain).unwrap(),
            scope,
            root,
            CallAttributionRole::CallSite,
            MarkerProbe::MacroDefinitionFirst,
            8,
        );

        let prepared = PreparedRootProgramTraversal::prepare(
            &workspace,
            &index,
            &authority,
            &request,
            &mut ExpandPolicy,
        )
        .unwrap();
        let resolved = resolve_prepared(prepared, &workspace, &registry);
        assert_eq!(
            resolved.occurrence_visits()[0]
                .attached_marker_candidates()
                .len(),
            expected_candidates,
            "candidate filtering differs for case {ordinal}"
        );
    }
}

#[test]
fn recursive_function_candidate_is_endpoint_local_and_never_changes_the_visit_key() {
    let registry = registry();
    let scope = ArtifactScopeId::for_in_memory(42, 0);
    let root = FunctionKey::new(definition(42, 1), Some(instance(1)));
    let domain = "sniff-test.test.function-marker-local";
    let artifact = configured_call_artifact(
        &registry,
        root,
        root,
        &ConfiguredCall {
            kind: CallKind::DirectCall,
            attribution: vec![CallAttributionRole::CallSite],
            callable_key: None,
            target: TargetFixture::Root,
            call_count: 1,
            route: CallRoute::Site,
            marker: Some((
                MarkerEndpoint::Function,
                domain,
                MarkerMatch::SourceCallsite,
            )),
        },
    );
    let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
    let workspace = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
    let index =
        WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 42)])
            .unwrap();
    let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
    let indexed_candidate = index.function_marker_candidates(&scope, &root).unwrap()[0].clone();
    let indexed_claim_data = index
        .exact_marker_claim(&scope, indexed_candidate.claim())
        .unwrap()
        .data()
        .clone();
    let mut policy = ObservingFollowPolicy::default();
    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request(domain, scope, root),
        &mut policy,
    )
    .unwrap();

    assert_eq!(policy.body_marker_counts, vec![(0, 1)]);
    assert_eq!(policy.call_marker_counts, vec![(0, 0, 0)]);
    let resolved = resolve_prepared(prepared, &workspace, &registry);
    let [body] = resolved.body_visits() else {
        panic!("the endpoint-local claim must not manufacture a second marker-state visit");
    };
    assert!(body.active_markers().is_empty());
    let [candidate] = body.endpoint_marker_candidates() else {
        panic!("the function candidate must remain visible on its endpoint");
    };
    assert_eq!(candidate.claim(), indexed_candidate.claim_id());
    assert_eq!(candidate.data(), &indexed_claim_data);
    assert_eq!(
        candidate.trace().relations().last(),
        Some(&WorkspaceRelationRef::Artifact(
            indexed_candidate.relation().clone()
        ))
    );
    assert!(resolved.occurrence_visits()[0].active_markers().is_empty());
    assert!(
        resolved
            .outcomes()
            .iter()
            .any(|outcome| outcome.kind() == &TraversalOutcomeKind::Cycle)
    );
}

#[test]
fn recursive_call_candidate_joins_before_policy_and_revisits_for_new_transported_state() {
    let registry = registry();
    let scope = ArtifactScopeId::for_in_memory(42, 1);
    let root = FunctionKey::new(definition(42, 2), Some(instance(2)));
    let domain = "sniff-test.test.call-marker-transport";
    let artifact = configured_call_artifact(
        &registry,
        root,
        root,
        &ConfiguredCall {
            kind: CallKind::DirectCall,
            attribution: vec![CallAttributionRole::CallSite],
            callable_key: None,
            target: TargetFixture::Root,
            call_count: 1,
            route: CallRoute::Site,
            marker: Some((MarkerEndpoint::Call, domain, MarkerMatch::SourceCallsite)),
        },
    );
    let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
    let workspace = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
    let index =
        WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 42)])
            .unwrap();
    let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
    let occurrence_key = CallOccurrenceKey::new(root, 0);
    let indexed_candidate = index
        .call_marker_candidates(&scope, &occurrence_key)
        .unwrap()[0]
        .clone();
    let indexed_claim_data = index
        .exact_marker_claim(&scope, indexed_candidate.claim())
        .unwrap()
        .data()
        .clone();
    let mut policy = ObservingFollowPolicy::default();
    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request(domain, scope, root),
        &mut policy,
    )
    .unwrap();

    assert_eq!(policy.body_marker_counts, vec![(0, 0), (1, 0)]);
    assert_eq!(
        policy.call_marker_counts,
        vec![(0, 1, 1), (1, 1, 1)],
        "the second attachment of the exact claim must be deduplicated in the active union"
    );
    let resolved = resolve_prepared(prepared, &workspace, &registry);
    assert_eq!(resolved.body_visits().len(), 2);
    assert!(resolved.body_visits()[0].active_markers().is_empty());
    assert_eq!(resolved.body_visits()[1].active_markers().len(), 1);
    assert_eq!(resolved.occurrence_visits().len(), 2);
    let first_call = &resolved.occurrence_visits()[0];
    assert!(first_call.inherited_markers().is_empty());
    assert_eq!(first_call.active_markers().len(), 1);
    assert_exact_call_marker_activation(first_call, &indexed_candidate, &indexed_claim_data);
    let second_call = &resolved.occurrence_visits()[1];
    assert_eq!(second_call.inherited_markers().len(), 1);
    assert_eq!(second_call.attached_marker_candidates().len(), 1);
    assert_eq!(second_call.active_markers().len(), 1);
    assert_eq!(
        second_call.inherited_markers()[0].claim(),
        second_call.attached_marker_candidates()[0].claim()
    );
    assert_eq!(resolved.followed_calls().len(), 2);
    for (followed, visit) in resolved
        .followed_calls()
        .iter()
        .zip(resolved.occurrence_visits())
    {
        assert_eq!(followed.occurrence(), visit.occurrence());
        assert_eq!(followed.source_anchors(), visit.source_anchors());
        assert_eq!(followed.macro_frames(), visit.macro_frames());
        assert_eq!(followed.inherited_markers(), visit.inherited_markers());
        assert_eq!(
            followed.attached_marker_candidates(),
            visit.attached_marker_candidates()
        );
        assert_eq!(followed.active_markers(), visit.active_markers());
    }
    assert!(resolved.followed_calls()[0].inherited_markers().is_empty());
    assert_eq!(resolved.followed_calls()[1].inherited_markers().len(), 1);
    assert!(
        resolved
            .outcomes()
            .iter()
            .any(|outcome| outcome.kind() == &TraversalOutcomeKind::Cycle)
    );
}

#[test]
fn different_transported_marker_states_revisit_one_body_and_consume_budget_separately() {
    let registry = registry();
    let scope = ArtifactScopeId::for_in_memory(42, 2);
    let root = FunctionKey::new(definition(42, 3), Some(instance(3)));
    let target = FunctionKey::new(definition(42, 4), Some(instance(4)));
    let domain = "sniff-test.test.marker-state-budget";
    let config = ConfiguredCall {
        kind: CallKind::DirectCall,
        attribution: vec![CallAttributionRole::CallSite],
        callable_key: None,
        target: TargetFixture::None,
        call_count: 2,
        route: CallRoute::Site,
        marker: None,
    };
    let mut artifact_builder = ConfiguredCallArtifactBuilder::new(&registry, root);
    let target_callable = artifact_builder
        .insert_target(target, TargetFixture::SeparateWithBody)
        .unwrap();
    let occurrences = artifact_builder.insert_calls_all(&config, Some(&target_callable));
    artifact_builder.insert_marker(
        MarkerEndpoint::Call,
        domain,
        MarkerMatch::SourceCallsite,
        Some(&occurrences[0]),
    );
    artifact_builder.insert_effect(target, 0, 0);
    let artifact = artifact_builder.finish(&registry);
    let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
    let workspace = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
    let index =
        WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 42)])
            .unwrap();
    let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
    let request = RootProgramTraversalRequest::new(
        DomainId::new(domain).unwrap(),
        scope,
        root,
        CallAttributionRole::CallSite,
        MarkerProbe::SourceCallsite,
        2,
    );
    let mut policy = ObservingFollowPolicy::default();
    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request,
        &mut policy,
    )
    .unwrap();

    assert_eq!(
        policy.body_marker_counts,
        vec![(0, 0), (1, 0), (0, 0)],
        "the same target with a different transported set remains a distinct policy visit"
    );
    assert_eq!(policy.call_marker_counts, vec![(0, 1, 1), (0, 0, 0)]);
    assert_eq!(prepared.body_visits.len(), 2);
    assert_eq!(prepared.effect_visits.len(), 1);
    assert_eq!(prepared.effect_visits[0].inherited_markers.0.len(), 1);
    assert!(
        prepared
            .outcomes
            .iter()
            .any(|outcome| outcome.kind == TraversalOutcomeKind::BudgetExceeded { limit: 2 })
    );
    assert!(
        !prepared
            .outcomes
            .iter()
            .any(|outcome| outcome.kind == TraversalOutcomeKind::Deduplicated)
    );
}

#[test]
fn distinct_transported_marker_states_visit_the_same_effect_independently() {
    let registry = registry();
    let scope = ArtifactScopeId::for_in_memory(42, 4);
    let root = FunctionKey::new(definition(42, 7), Some(instance(7)));
    let target = FunctionKey::new(definition(42, 8), Some(instance(8)));
    let domain = "sniff-test.test.effect-marker-state";
    let config = ConfiguredCall {
        kind: CallKind::DirectCall,
        attribution: vec![CallAttributionRole::CallSite],
        callable_key: None,
        target: TargetFixture::None,
        call_count: 2,
        route: CallRoute::Site,
        marker: None,
    };
    let mut fixture = ConfiguredCallArtifactBuilder::new(&registry, root);
    let target_callable = fixture
        .insert_target(target, TargetFixture::SeparateWithBody)
        .unwrap();
    let occurrences = fixture.insert_calls_all(&config, Some(&target_callable));
    fixture.insert_marker(
        MarkerEndpoint::Call,
        domain,
        MarkerMatch::SourceCallsite,
        Some(&occurrences[0]),
    );
    fixture.insert_effect(target, 0, 0);
    let artifact = fixture.finish(&registry);
    let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
    let workspace = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
    let index =
        WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 42)])
            .unwrap();
    let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &RootProgramTraversalRequest::new(
            DomainId::new(domain).unwrap(),
            scope,
            root,
            CallAttributionRole::CallSite,
            MarkerProbe::SourceCallsite,
            3,
        ),
        &mut FollowRuntimePolicy,
    )
    .unwrap();
    let traversal = resolve_prepared(prepared, &workspace, &registry);

    assert_eq!(traversal.body_visits().len(), 3);
    let [marked, unmarked] = traversal.effect_visits() else {
        panic!("the same effect is visited under both transported states")
    };
    assert_eq!(marked.effect(), unmarked.effect());
    assert_eq!(marked.inherited_markers().len(), 1);
    assert!(unmarked.inherited_markers().is_empty());
    assert_ne!(marked.trace(), unmarked.trace());
    assert!(
        !traversal
            .outcomes()
            .iter()
            .any(|outcome| outcome.kind() == &TraversalOutcomeKind::Deduplicated)
    );
}

#[test]
fn identical_transported_claim_sets_deduplicate_after_the_first_completed_route() {
    let registry = registry();
    let scope = ArtifactScopeId::for_in_memory(42, 3);
    let root = FunctionKey::new(definition(42, 5), Some(instance(5)));
    let target = FunctionKey::new(definition(42, 6), Some(instance(6)));
    let domain = "sniff-test.test.marker-state-dedup";
    let config = ConfiguredCall {
        kind: CallKind::DirectCall,
        attribution: vec![CallAttributionRole::CallSite],
        callable_key: None,
        target: TargetFixture::None,
        call_count: 2,
        route: CallRoute::Site,
        marker: None,
    };
    let mut artifact_builder = ConfiguredCallArtifactBuilder::new(&registry, root);
    let target_callable = artifact_builder
        .insert_target(target, TargetFixture::SeparateWithBody)
        .unwrap();
    let occurrences = artifact_builder.insert_calls_all(&config, Some(&target_callable));
    let claim = artifact_builder.insert_marker(
        MarkerEndpoint::Call,
        domain,
        MarkerMatch::SourceCallsite,
        Some(&occurrences[0]),
    );
    artifact_builder.attach_call_marker(&occurrences[1], &claim, MarkerMatch::SourceCallsite);
    let artifact = artifact_builder.finish(&registry);
    let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
    let workspace = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
    let index =
        WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 42)])
            .unwrap();
    let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
    let mut policy = ObservingFollowPolicy::default();
    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request(domain, scope, root),
        &mut policy,
    )
    .unwrap();

    assert_eq!(policy.body_marker_counts, vec![(0, 0), (1, 0)]);
    assert_eq!(policy.call_marker_counts, vec![(0, 1, 1), (0, 1, 1)]);
    assert_eq!(prepared.body_visits.len(), 2);
    assert!(
        prepared
            .outcomes
            .iter()
            .any(|outcome| outcome.kind == TraversalOutcomeKind::Deduplicated)
    );
    let resolved = resolve_prepared(prepared, &workspace, &registry);
    assert_eq!(resolved.occurrence_visits().len(), 2);
    assert_eq!(resolved.occurrence_visits()[0].active_markers().len(), 1);
    assert_eq!(resolved.occurrence_visits()[1].active_markers().len(), 1);
    assert_eq!(
        resolved.occurrence_visits()[0].active_markers()[0].claim(),
        resolved.occurrence_visits()[1].active_markers()[0].claim()
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one fixture contrasts function and call boundaries with an ignored call"
)]
fn marker_candidates_are_retained_at_body_and_call_boundaries_without_propagation() {
    let registry = registry();
    let root = FunctionKey::new(definition(43, 1), Some(instance(1)));
    let target = FunctionKey::new(definition(43, 2), Some(instance(2)));
    let domain = "sniff-test.test.marker-boundaries";

    let function_scope = ArtifactScopeId::for_in_memory(43, 0);
    let function_artifact = configured_call_artifact(
        &registry,
        root,
        target,
        &ConfiguredCall {
            kind: CallKind::DirectCall,
            attribution: vec![CallAttributionRole::CallSite],
            callable_key: None,
            target: TargetFixture::SeparateWithBody,
            call_count: 1,
            route: CallRoute::Site,
            marker: Some((
                MarkerEndpoint::Function,
                domain,
                MarkerMatch::SourceCallsite,
            )),
        },
    );
    let function_view = ArtifactDbView::open(&function_artifact, registry.schemas()).unwrap();
    let function_workspace =
        WorkspaceFactView::compose([(function_scope.clone(), function_view)]).unwrap();
    let function_index = WorkspaceProgramIndex::open(
        &function_workspace,
        [VerifiedArtifactOwner::new(function_scope.clone(), 43)],
    )
    .unwrap();
    let function_authority =
        VerifiedDefiningScopeMap::new(&function_workspace, &function_index, []).unwrap();
    let function_prepared = PreparedRootProgramTraversal::prepare(
        &function_workspace,
        &function_index,
        &function_authority,
        &request(domain, function_scope, root),
        &mut BoundaryPolicy,
    )
    .unwrap();
    let function_resolved = resolve_prepared(function_prepared, &function_workspace, &registry);
    let [body_boundary] = function_resolved.body_boundaries() else {
        panic!("the body policy should stop at the root");
    };
    assert!(body_boundary.active_markers().is_empty());
    assert_eq!(body_boundary.endpoint_marker_candidates().len(), 1);
    assert!(function_resolved.occurrence_visits().is_empty());

    let call_scope = ArtifactScopeId::for_in_memory(43, 1);
    let call_artifact = configured_call_artifact(
        &registry,
        root,
        target,
        &ConfiguredCall {
            kind: CallKind::DirectCall,
            attribution: vec![CallAttributionRole::CallSite],
            callable_key: None,
            target: TargetFixture::SeparateWithBody,
            call_count: 1,
            route: CallRoute::Site,
            marker: Some((MarkerEndpoint::Call, domain, MarkerMatch::SourceCallsite)),
        },
    );
    let call_view = ArtifactDbView::open(&call_artifact, registry.schemas()).unwrap();
    let call_workspace = WorkspaceFactView::compose([(call_scope.clone(), call_view)]).unwrap();
    let call_index = WorkspaceProgramIndex::open(
        &call_workspace,
        [VerifiedArtifactOwner::new(call_scope.clone(), 43)],
    )
    .unwrap();
    let call_authority = VerifiedDefiningScopeMap::new(&call_workspace, &call_index, []).unwrap();
    let call_prepared = PreparedRootProgramTraversal::prepare(
        &call_workspace,
        &call_index,
        &call_authority,
        &request(domain, call_scope.clone(), root),
        &mut CallBoundaryPolicy,
    )
    .unwrap();
    let call_resolved = resolve_prepared(call_prepared, &call_workspace, &registry);
    let [call_boundary] = call_resolved.call_boundaries() else {
        panic!("the call policy should retain one boundary");
    };
    assert!(call_boundary.inherited_markers().is_empty());
    assert_eq!(call_boundary.attached_marker_candidates().len(), 1);
    assert_eq!(call_boundary.active_markers().len(), 1);
    assert!(call_boundary.macro_frames().is_empty());
    assert!(call_boundary.target().is_some());
    assert!(call_resolved.followed_calls().is_empty());
    assert_eq!(call_resolved.body_visits().len(), 1);

    let followed_boundary = PreparedRootProgramTraversal::prepare(
        &call_workspace,
        &call_index,
        &call_authority,
        &request(domain, call_scope.clone(), root),
        &mut FollowAndBoundaryPolicy,
    )
    .unwrap();
    let followed_boundary = resolve_prepared(followed_boundary, &call_workspace, &registry);
    let [boundary] = followed_boundary.call_boundaries() else {
        panic!("the combined policy should retain one call boundary");
    };
    let [followed] = followed_boundary.followed_calls() else {
        panic!("the combined policy should also follow the call");
    };
    assert_eq!(boundary.order(), followed.order());
    assert_eq!(boundary.occurrence(), followed.occurrence());
    assert_eq!(boundary.target(), Some(followed.target()));
    assert_eq!(followed_boundary.body_visits().len(), 2);

    let ignored = PreparedRootProgramTraversal::prepare(
        &call_workspace,
        &call_index,
        &call_authority,
        &request(domain, call_scope, root),
        &mut ExpandPolicy,
    )
    .unwrap();
    let ignored = resolve_prepared(ignored, &call_workspace, &registry);
    assert!(ignored.call_boundaries().is_empty());
    assert!(ignored.followed_calls().is_empty());
}

#[test]
fn call_site_mode_registers_erasure_only_callable_evidence_without_policy() {
    let registry = registry();
    let scope = ArtifactScopeId::for_in_memory(9, 0);
    let root = FunctionKey::new(definition(9, 1), Some(instance(1)));
    let target = FunctionKey::new(definition(9, 2), Some(instance(2)));
    let artifact = configured_call_artifact(
        &registry,
        root,
        target,
        &ConfiguredCall {
            kind: CallKind::FnPointerReify,
            attribution: vec![CallAttributionRole::ErasureSite],
            callable_key: Some(CallableKey::FnPointer(type_hash(9))),
            target: TargetFixture::SeparateWithoutBody,
            call_count: 1,
            route: CallRoute::Site,
            marker: None,
        },
    );
    let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
    let workspace = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
    let index =
        WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 9)])
            .unwrap();
    let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
    let request = RootProgramTraversalRequest::new(
        DomainId::new("sniff-test.test.evidence").unwrap(),
        scope,
        root,
        CallAttributionRole::CallSite,
        MarkerProbe::SourceCallsite,
        8,
    );

    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request,
        &mut ExpandPolicy,
    )
    .unwrap();

    assert_eq!(prepared.occurrence_visits.len(), 1);
    assert!(prepared.call_boundaries.is_empty());
    assert!(prepared.callable_resolutions.is_empty());
    assert!(prepared.outcomes.is_empty());
}

#[test]
fn keyed_invocation_without_reached_evidence_runs_persisted_policy() {
    let registry = registry();
    let scope = ArtifactScopeId::for_in_memory(9, 1);
    let root = FunctionKey::new(definition(9, 3), Some(instance(3)));
    let unused_target = FunctionKey::new(definition(9, 4), Some(instance(4)));
    let artifact = configured_call_artifact(
        &registry,
        root,
        unused_target,
        &ConfiguredCall {
            kind: CallKind::IndirectCall,
            attribution: vec![CallAttributionRole::CallSite],
            callable_key: Some(CallableKey::FnPointer(type_hash(10))),
            target: TargetFixture::None,
            call_count: 1,
            route: CallRoute::Site,
            marker: None,
        },
    );
    let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
    let workspace = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
    let index =
        WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 9)])
            .unwrap();
    let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
    let request = RootProgramTraversalRequest::new(
        DomainId::new("sniff-test.test.invocation-key").unwrap(),
        scope,
        root,
        CallAttributionRole::CallSite,
        MarkerProbe::SourceCallsite,
        8,
    );

    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request,
        &mut ExpandPolicy,
    )
    .unwrap();

    assert_eq!(prepared.occurrence_visits.len(), 1);
    assert!(prepared.callable_resolutions.is_empty());
    assert!(matches!(
        prepared.outcomes.as_slice(),
        [outcome] if outcome.kind == TraversalOutcomeKind::Ignored
    ));
}

struct CallableFixpointFixture {
    artifact: ArtifactFactIr,
    root: FunctionKey,
    invocation: CallOccurrenceKey,
    evidence: CallOccurrenceKey,
    evidence_callable: FunctionKey,
    raw_callable: FunctionKey,
    source_contract: FunctionKey,
    callable_key: CallableKey,
}

fn callable_fixpoint_artifact(
    registry: &AnalysisRegistry<CollectedArtifact>,
    evidence_first: bool,
    nested_raw_call: bool,
    invocation_kind: CallKind,
    invocation_route: CallRoute,
) -> CallableFixpointFixture {
    let root = FunctionKey::new(definition(44, 1), Some(instance(1)));
    let evidence_callable = FunctionKey::new(definition(44, 2), Some(instance(2)));
    let raw_callable = FunctionKey::new(definition(44, 3), Some(instance(3)));
    let source_contract = FunctionKey::new(definition(44, 3), None);
    let callable_key = CallableKey::FnPointer(type_hash(44));
    let mut artifact = ConfiguredCallArtifactBuilder::new(registry, root);
    let evidence_target = artifact
        .insert_target(evidence_callable, TargetFixture::SeparateWithBody)
        .unwrap();
    let raw_target = artifact
        .insert_target(raw_callable, TargetFixture::SeparateWithBody)
        .unwrap();
    let source_target = artifact
        .insert_target(source_contract, TargetFixture::SeparateWithoutBody)
        .unwrap();
    let key = artifact
        .builder
        .insert_entity(&CallableKeyEntity::new(callable_key))
        .unwrap();
    let (evidence_local, invocation_local) = if evidence_first { (0, 1) } else { (1, 0) };
    artifact.insert_keyed_call_for(
        root,
        evidence_local,
        CallKind::FnPointerReify,
        vec![CallAttributionRole::ErasureSite],
        &key,
        &[(CallTargetRole::Runtime, evidence_target)],
    );
    let invocation = artifact.insert_keyed_call_for(
        root,
        invocation_local,
        invocation_kind,
        vec![CallAttributionRole::CallSite],
        &key,
        &[
            (CallTargetRole::Runtime, raw_target),
            (CallTargetRole::SourceContract, source_target),
        ],
    );
    if matches!(invocation_route, CallRoute::Macro) {
        artifact.insert_macro_route(*invocation.key(), &invocation, invocation_local);
    }
    artifact.insert_marker(
        MarkerEndpoint::Call,
        "sniff-test.test.callable-fixpoint",
        MarkerMatch::SourceCallsite,
        Some(&invocation),
    );
    if nested_raw_call {
        let root_target = artifact.root_callable.clone();
        artifact.insert_call_for(raw_callable, 0, Some(&root_target));
    }
    CallableFixpointFixture {
        artifact: artifact.finish(registry),
        root,
        invocation: CallOccurrenceKey::new(root, invocation_local),
        evidence: CallOccurrenceKey::new(root, evidence_local),
        evidence_callable,
        raw_callable,
        source_contract,
        callable_key,
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one fixture checks both arrival orders and every retained trace facet"
)]
fn callable_evidence_fixpoint_is_arrival_order_independent_and_retains_exact_traces() {
    let registry = registry();
    for (generation, evidence_first) in [(0, true), (1, false)] {
        let fixture = callable_fixpoint_artifact(
            &registry,
            evidence_first,
            false,
            CallKind::IndirectCall,
            CallRoute::Site,
        );
        let scope = ArtifactScopeId::for_in_memory(44, generation);
        let workspace = WorkspaceFactView::compose([(
            scope.clone(),
            ArtifactDbView::open(&fixture.artifact, registry.schemas()).unwrap(),
        )])
        .unwrap();
        let index = WorkspaceProgramIndex::open(
            &workspace,
            [VerifiedArtifactOwner::new(scope.clone(), 44)],
        )
        .unwrap();
        let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
        let mut policy = RecordingCallPolicy::default();
        let prepared = PreparedRootProgramTraversal::prepare(
            &workspace,
            &index,
            &authority,
            &request(
                "sniff-test.test.callable-fixpoint",
                scope.clone(),
                fixture.root,
            ),
            &mut policy,
        )
        .unwrap();

        assert_eq!(policy.calls.len(), 2);
        assert_eq!(policy.calls[0].occurrence, fixture.invocation);
        assert_eq!(policy.calls[0].effective_kind, CallKind::IndirectCall);
        assert_eq!(policy.calls[0].resolution, ProgramCallResolution::Persisted);
        assert_eq!(policy.calls[0].marker_counts, (0, 1, 1));
        assert_eq!(
            policy.calls[0].targets,
            vec![
                (CallTargetRole::Runtime, fixture.raw_callable, scope.clone()),
                (
                    CallTargetRole::SourceContract,
                    fixture.source_contract,
                    scope.clone(),
                ),
            ]
        );
        assert_eq!(policy.calls[1].occurrence, fixture.invocation);
        assert_eq!(
            policy.calls[1].effective_kind,
            CallKind::FnPointerCallTarget
        );
        assert!(matches!(
            policy.calls[1].resolution,
            ProgramCallResolution::CallableEvidence {
                key,
                kind: CallableResolutionKind::FunctionPointerEvidence,
                ..
            } if key == fixture.callable_key
        ));
        assert_eq!(policy.calls[1].marker_counts, (0, 1, 1));
        assert_eq!(
            policy.calls[1].targets,
            vec![
                (
                    CallTargetRole::Runtime,
                    fixture.evidence_callable,
                    scope.clone(),
                ),
                (
                    CallTargetRole::SourceContract,
                    fixture.source_contract,
                    scope.clone(),
                ),
            ]
        );
        assert_eq!(prepared.callable_resolutions.len(), 1);
        let resolved = resolve_prepared(prepared, &workspace, &registry);
        let [resolution] = resolved.callable_resolutions() else {
            panic!("one reached callable-evidence join must resolve");
        };
        assert_eq!(resolution.invocation_data().key(), &fixture.invocation);
        assert_eq!(resolution.evidence_data().key(), &fixture.evidence);
        assert_eq!(resolution.callable_data().key(), &fixture.evidence_callable);
        assert_eq!(resolution.key(), fixture.callable_key);
        assert_eq!(
            resolution.kind(),
            CallableResolutionKind::FunctionPointerEvidence
        );
        assert_eq!(
            resolution
                .resolution_trace()
                .relations()
                .last()
                .map(|relation| relation.schema().as_str()),
            Some(CallableInvocationTargetsCallable::ID)
        );
        assert_eq!(
            resolution.evidence_trace().target(),
            &resolution.evidence().erase()
        );
        assert_eq!(
            resolution
                .evidence_trace()
                .relations()
                .last()
                .map(|relation| relation.schema().as_str()),
            Some(CallSiteHasOccurrence::ID)
        );
    }
}

#[test]
fn raw_and_synthetic_boundaries_retain_the_invocations_exact_macro_frames() {
    let registry = registry();
    let fixture = callable_fixpoint_artifact(
        &registry,
        true,
        false,
        CallKind::IndirectCall,
        CallRoute::Macro,
    );
    let scope = ArtifactScopeId::for_in_memory(44, 4);
    let workspace = WorkspaceFactView::compose([(
        scope.clone(),
        ArtifactDbView::open(&fixture.artifact, registry.schemas()).unwrap(),
    )])
    .unwrap();
    let index =
        WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 44)])
            .unwrap();
    let indexed_path = index
        .call_macro_path(&scope, &fixture.invocation)
        .unwrap()
        .expect("invocation has an exact macro path")
        .clone();
    let callsite_relation = WorkspaceRelationRef::Artifact(
        indexed_path.callsites()[0]
            .as_ref()
            .expect("outer frame has a callsite")
            .relation()
            .clone(),
    );
    let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request("sniff-test.test.callable-macro-frames", scope, fixture.root),
        &mut CallBoundaryPolicy,
    )
    .unwrap();
    let resolved = resolve_prepared(prepared, &workspace, &registry);
    let invocation = resolved
        .occurrence_visits()
        .iter()
        .find(|visit| visit.data().key() == &fixture.invocation)
        .expect("raw invocation is visited");

    assert_eq!(invocation.macro_frames().len(), 2);
    assert!(invocation.macro_frames()[0].callsite().is_some());
    assert!(invocation.macro_frames()[1].callsite().is_none());
    assert_eq!(resolved.call_boundaries().len(), 2);
    assert!(
        resolved
            .call_boundaries()
            .iter()
            .any(|boundary| boundary.resolution() == &ProgramCallResolution::Persisted)
    );
    assert!(resolved.call_boundaries().iter().any(|boundary| matches!(
        boundary.resolution(),
        ProgramCallResolution::CallableEvidence { .. }
    )));
    for boundary in resolved.call_boundaries() {
        assert_eq!(boundary.macro_frames(), invocation.macro_frames());
        assert!(!boundary.trace().relations().contains(&callsite_relation));
    }
    assert!(resolved.followed_calls().is_empty());
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "both arrival orders must prove the complete raw and evidence-follow snapshots"
)]
fn raw_and_callable_evidence_follows_are_distinct_exact_and_arrival_order_independent() {
    let registry = registry();
    let mut expected_projection = None;
    for (generation, evidence_first) in [(5, true), (6, false)] {
        let fixture = callable_fixpoint_artifact(
            &registry,
            evidence_first,
            false,
            CallKind::IndirectCall,
            CallRoute::Macro,
        );
        let scope = ArtifactScopeId::for_in_memory(44, generation);
        let workspace = WorkspaceFactView::compose([(
            scope.clone(),
            ArtifactDbView::open(&fixture.artifact, registry.schemas()).unwrap(),
        )])
        .unwrap();
        let index = WorkspaceProgramIndex::open(
            &workspace,
            [VerifiedArtifactOwner::new(scope.clone(), 44)],
        )
        .unwrap();
        let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
        let prepared = PreparedRootProgramTraversal::prepare(
            &workspace,
            &index,
            &authority,
            &request(
                "sniff-test.test.callable-fixpoint",
                scope.clone(),
                fixture.root,
            ),
            &mut FollowEveryRuntimePolicy::default(),
        )
        .unwrap();
        let resolved = resolve_prepared(prepared, &workspace, &registry);
        let invocation = resolved
            .occurrence_visits()
            .iter()
            .find(|visit| visit.data().key() == &fixture.invocation)
            .expect("the invocation is visited exactly");
        let [raw, synthetic] = resolved.followed_calls() else {
            panic!("raw and reached callable-evidence policy snapshots both follow");
        };
        let indexed_occurrence = index
            .exact_call_occurrence(&scope, &fixture.invocation)
            .unwrap();
        let indexed_call_site = index
            .exact_call_site(
                &scope,
                &CallSiteKey::new(fixture.root, fixture.invocation.local_id()),
            )
            .unwrap();
        let indexed_safety_group = index
            .exact_safety_group(
                &scope,
                &SafetyEffectGroupKey::new(fixture.root, fixture.invocation.local_id()),
            )
            .unwrap();
        let raw_callable = index.exact_callable(&scope, &fixture.raw_callable).unwrap();
        let evidence_callable = index
            .exact_callable(&scope, &fixture.evidence_callable)
            .unwrap();
        let evidence_occurrence = index
            .exact_call_occurrence(&scope, &fixture.evidence)
            .unwrap();

        for followed in [raw, synthetic] {
            assert_eq!(followed.occurrence(), &indexed_occurrence.id());
            assert_eq!(followed.occurrence_data(), indexed_occurrence.data());
            assert_eq!(followed.call_site(), &indexed_call_site.id());
            assert_eq!(followed.call_site_data(), indexed_call_site.data());
            assert_eq!(followed.safety_group(), &indexed_safety_group.id());
            assert_eq!(followed.safety_group_data(), indexed_safety_group.data());
            assert_eq!(followed.kind(), CallKind::IndirectCall);
            assert_eq!(followed.target().role(), CallTargetRole::Runtime);
            assert_eq!(
                followed.target().authority(),
                ReconciledCallTargetAuthority::ConsumerRaw
            );
            assert_eq!(followed.source_anchors(), invocation.source_anchors());
            assert_eq!(followed.macro_frames(), invocation.macro_frames());
            assert_eq!(followed.inherited_markers(), invocation.inherited_markers());
            assert_eq!(
                followed.attached_marker_candidates(),
                invocation.attached_marker_candidates()
            );
            assert_eq!(followed.active_markers(), invocation.active_markers());
            assert_eq!(followed.attached_marker_candidates().len(), 1);
            assert_eq!(followed.active_markers().len(), 1);
            assert_eq!(
                followed.trace().target(),
                &followed.target().callable().erase()
            );
        }
        assert!(raw.order() < synthetic.order());
        assert_eq!(raw.effective_kind(), CallKind::IndirectCall);
        assert_eq!(raw.resolution(), &ProgramCallResolution::Persisted);
        assert_eq!(raw.target().callable(), &raw_callable.id());
        assert_eq!(raw.target_data(), raw_callable.data());
        assert_eq!(
            raw.trace()
                .relations()
                .last()
                .map(|relation| relation.schema().as_str()),
            Some(CallOccurrenceTargetsCallable::ID)
        );
        assert_eq!(synthetic.effective_kind(), CallKind::FnPointerCallTarget);
        assert!(matches!(
            synthetic.resolution(),
            ProgramCallResolution::CallableEvidence {
                evidence,
                key,
                kind: CallableResolutionKind::FunctionPointerEvidence,
            } if evidence == &evidence_occurrence.id() && *key == fixture.callable_key
        ));
        assert_eq!(synthetic.target().callable(), &evidence_callable.id());
        assert_eq!(synthetic.target_data(), evidence_callable.data());
        assert_eq!(
            synthetic
                .trace()
                .relations()
                .last()
                .map(|relation| relation.schema().as_str()),
            Some(CallableInvocationTargetsCallable::ID)
        );

        let projection = resolved
            .followed_calls()
            .iter()
            .map(|followed| {
                (
                    followed.effective_kind(),
                    *followed.target_data().key(),
                    matches!(
                        followed.resolution(),
                        ProgramCallResolution::CallableEvidence { .. }
                    ),
                    followed
                        .trace()
                        .relations()
                        .iter()
                        .map(|relation| relation.schema().as_str().to_owned())
                        .collect::<Vec<_>>(),
                    followed
                        .macro_frames()
                        .iter()
                        .map(|frame| frame.callsite().is_some())
                        .collect::<Vec<_>>(),
                    followed.active_markers().len(),
                )
            })
            .collect::<Vec<_>>();
        if let Some(expected) = &expected_projection {
            assert_eq!(&projection, expected);
        } else {
            expected_projection = Some(projection);
        }
    }
}

#[test]
fn raw_selected_body_is_expanded_before_the_synthetic_selected_body() {
    let registry = registry();
    let fixture = callable_fixpoint_artifact(
        &registry,
        true,
        true,
        CallKind::IndirectCall,
        CallRoute::Site,
    );
    let scope = ArtifactScopeId::for_in_memory(44, 2);
    let workspace = WorkspaceFactView::compose([(
        scope.clone(),
        ArtifactDbView::open(&fixture.artifact, registry.schemas()).unwrap(),
    )])
    .unwrap();
    let index =
        WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 44)])
            .unwrap();
    let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();

    let mut policy = FollowEveryRuntimePolicy::default();
    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request(
            "sniff-test.test.callable-fixpoint-order",
            scope,
            fixture.root,
        ),
        &mut policy,
    )
    .unwrap();

    assert_eq!(
        prepared
            .body_visits
            .iter()
            .map(|visit| *visit.data.key())
            .collect::<Vec<_>>(),
        vec![
            fixture.root,
            fixture.raw_callable,
            fixture.evidence_callable
        ]
    );
    assert_eq!(
        policy.calls,
        vec![
            fixture.invocation,
            CallOccurrenceKey::new(fixture.raw_callable, 0),
            fixture.invocation,
        ]
    );
    let nested_cycle_order = prepared
        .outcomes
        .iter()
        .find(|outcome| outcome.kind == TraversalOutcomeKind::Cycle)
        .expect("the nested raw call reaches the still-active root")
        .order;
    assert!(nested_cycle_order < prepared.callable_resolutions[0].order);
}

#[test]
fn synthetic_target_kinds_do_not_reenter_callable_resolution() {
    let registry = registry();
    let fixture = callable_fixpoint_artifact(
        &registry,
        true,
        false,
        CallKind::FnPointerCallTarget,
        CallRoute::Site,
    );
    let scope = ArtifactScopeId::for_in_memory(44, 3);
    let workspace = WorkspaceFactView::compose([(
        scope.clone(),
        ArtifactDbView::open(&fixture.artifact, registry.schemas()).unwrap(),
    )])
    .unwrap();
    let index =
        WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 44)])
            .unwrap();
    let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
    let mut policy = RecordingCallPolicy::default();

    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request("sniff-test.test.no-synthetic-reentry", scope, fixture.root),
        &mut policy,
    )
    .unwrap();

    assert_eq!(
        policy.calls.len(),
        1,
        "the persisted call still reaches policy"
    );
    assert_eq!(policy.calls[0].resolution, ProgramCallResolution::Persisted);
    assert!(prepared.callable_resolutions.is_empty());
}

#[test]
fn same_scope_unreached_evidence_never_resolves_a_reached_invocation() {
    let registry = registry();
    let scope = ArtifactScopeId::for_in_memory(45, 0);
    let root = FunctionKey::new(definition(45, 1), Some(instance(1)));
    let evidence_owner = FunctionKey::new(definition(45, 2), Some(instance(2)));
    let evidence_target = FunctionKey::new(definition(45, 3), Some(instance(3)));
    let key = CallableKey::FnPointer(type_hash(45));
    let mut artifact = ConfiguredCallArtifactBuilder::new(&registry, root);
    artifact.insert_target(evidence_owner, TargetFixture::SeparateWithBody);
    let target = artifact
        .insert_target(evidence_target, TargetFixture::SeparateWithoutBody)
        .unwrap();
    let callable_key = artifact
        .builder
        .insert_entity(&CallableKeyEntity::new(key))
        .unwrap();
    artifact.insert_keyed_call_for(
        root,
        0,
        CallKind::IndirectCall,
        vec![CallAttributionRole::CallSite],
        &callable_key,
        &[],
    );
    artifact.insert_keyed_call_for(
        evidence_owner,
        0,
        CallKind::FnPointerReify,
        vec![CallAttributionRole::ErasureSite],
        &callable_key,
        &[(CallTargetRole::Runtime, target)],
    );
    let artifact = artifact.finish(&registry);
    let workspace = WorkspaceFactView::compose([(
        scope.clone(),
        ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
    )])
    .unwrap();
    let index =
        WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 45)])
            .unwrap();
    let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();

    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request("sniff-test.test.unreached-evidence", scope, root),
        &mut ExpandPolicy,
    )
    .unwrap();

    assert!(prepared.callable_resolutions.is_empty());
    assert_eq!(prepared.occurrence_visits.len(), 1);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the cross-scope fixture must establish and verify both exact generations"
)]
fn reached_cross_scope_evidence_resolves_without_transporting_its_markers() {
    let registry = registry();
    let invocation_scope = ArtifactScopeId::for_in_memory(46, 0);
    let evidence_scope = ArtifactScopeId::for_in_memory(47, 0);
    let invocation_root = FunctionKey::new(definition(46, 1), Some(instance(1)));
    let evidence_root = FunctionKey::new(definition(47, 1), Some(instance(1)));
    let evidence_target = FunctionKey::new(definition(47, 2), Some(instance(2)));
    let key = CallableKey::FnPointer(type_hash(46));
    let mut invocation_builder = ConfiguredCallArtifactBuilder::new(&registry, invocation_root);
    let bridge_target = invocation_builder
        .insert_target(evidence_root, TargetFixture::SeparateWithoutBody)
        .unwrap();
    let invocation_key = invocation_builder
        .builder
        .insert_entity(&CallableKeyEntity::new(key))
        .unwrap();
    invocation_builder.insert_keyed_call_for(
        invocation_root,
        0,
        CallKind::IndirectCall,
        vec![CallAttributionRole::CallSite],
        &invocation_key,
        &[],
    );
    let bridge = invocation_builder.insert_call_for(invocation_root, 1, Some(&bridge_target));
    let invocation_artifact = invocation_builder.finish(&registry);
    let mut evidence_builder = ConfiguredCallArtifactBuilder::new(&registry, evidence_root);
    let target = evidence_builder
        .insert_target(evidence_target, TargetFixture::SeparateWithoutBody)
        .unwrap();
    let callable_key = evidence_builder
        .builder
        .insert_entity(&CallableKeyEntity::new(key))
        .unwrap();
    let evidence = evidence_builder.insert_keyed_call_for(
        evidence_root,
        0,
        CallKind::FnPointerReify,
        vec![CallAttributionRole::ErasureSite],
        &callable_key,
        &[(CallTargetRole::Runtime, target)],
    );
    evidence_builder.insert_marker(
        MarkerEndpoint::Call,
        "sniff-test.test.cross-scope-evidence",
        MarkerMatch::SourceCallsite,
        Some(&evidence),
    );
    let evidence_artifact = evidence_builder.finish(&registry);
    let workspace = WorkspaceFactView::compose([
        (
            invocation_scope.clone(),
            ArtifactDbView::open(&invocation_artifact, registry.schemas()).unwrap(),
        ),
        (
            evidence_scope.clone(),
            ArtifactDbView::open(&evidence_artifact, registry.schemas()).unwrap(),
        ),
    ])
    .unwrap();
    let index = WorkspaceProgramIndex::open(
        &workspace,
        [
            VerifiedArtifactOwner::new(invocation_scope.clone(), 46),
            VerifiedArtifactOwner::new(evidence_scope.clone(), 47),
        ],
    )
    .unwrap();
    let authority = VerifiedDefiningScopeMap::new(
        &workspace,
        &index,
        [DefiningScopeAuthority::new(
            invocation_scope.clone(),
            47,
            StableCrateResolution::Managed(evidence_scope.clone()),
        )],
    )
    .unwrap();
    let mut policy = ReachBridgeThenRecordPolicy {
        bridge: *bridge.key(),
        recorded: RecordingCallPolicy::default(),
    };
    let request = request(
        "sniff-test.test.cross-scope-evidence",
        invocation_scope.clone(),
        invocation_root,
    );
    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request,
        &mut policy,
    )
    .unwrap();
    assert_eq!(prepared.callable_resolutions.len(), 1);
    assert_eq!(policy.recorded.calls.len(), 2);
    assert_eq!(policy.recorded.calls[0].marker_counts, (0, 0, 0));
    assert_eq!(policy.recorded.calls[1].marker_counts, (0, 0, 0));
    assert!(matches!(
        policy.recorded.calls[1].resolution,
        ProgramCallResolution::CallableEvidence { .. }
    ));
    assert_eq!(
        policy.recorded.calls[1].targets,
        vec![(
            CallTargetRole::Runtime,
            evidence_target,
            evidence_scope.clone(),
        )]
    );
    let evidence_visit = prepared
        .occurrence_visits
        .iter()
        .find(|visit| visit.occurrence.scope() == &evidence_scope)
        .expect("the evidence occurrence is reached through the managed body");
    assert_eq!(evidence_visit.active_markers.0.len(), 1);
    let resolved = resolve_prepared(prepared, &workspace, &registry);
    let [resolution] = resolved.callable_resolutions() else {
        panic!("one cross-scope callable resolution must resolve");
    };
    assert_eq!(resolution.invocation().scope(), &invocation_scope);
    assert_eq!(resolution.evidence().scope(), &evidence_scope);
    assert_eq!(resolution.callable().scope(), &evidence_scope);
}

#[test]
fn duplicate_callable_resolutions_keep_the_first_reached_evidence_across_keys() {
    let registry = registry();
    let scope = ArtifactScopeId::for_in_memory(48, 0);
    let root = FunctionKey::new(definition(48, 1), Some(instance(1)));
    let target = FunctionKey::new(definition(48, 2), Some(instance(2)));
    let first_key = CallableKey::FnPointer(type_hash(999));
    let second_key = CallableKey::FnPointer(type_hash(1));
    let mut artifact = ConfiguredCallArtifactBuilder::new(&registry, root);
    let callable = artifact
        .insert_target(target, TargetFixture::SeparateWithoutBody)
        .unwrap();
    let first_key_entity = artifact
        .builder
        .insert_entity(&CallableKeyEntity::new(first_key))
        .unwrap();
    let second_key_entity = artifact
        .builder
        .insert_entity(&CallableKeyEntity::new(second_key))
        .unwrap();
    artifact.insert_keyed_call_for(
        root,
        0,
        CallKind::FnPointerReify,
        vec![CallAttributionRole::ErasureSite],
        &first_key_entity,
        &[(CallTargetRole::Runtime, callable.clone())],
    );
    artifact.insert_keyed_call_for(
        root,
        1,
        CallKind::ClosureFnPointerReify,
        vec![CallAttributionRole::ErasureSite],
        &second_key_entity,
        &[(CallTargetRole::Runtime, callable)],
    );
    let invocation = artifact.insert_keyed_call_for(
        root,
        2,
        CallKind::IndirectCall,
        vec![CallAttributionRole::CallSite],
        &second_key_entity,
        &[],
    );
    artifact
        .builder
        .relate(
            &invocation,
            &first_key_entity,
            &CallOccurrenceHasCallableKey::new(),
        )
        .unwrap();
    let artifact = artifact.finish(&registry);
    let workspace = WorkspaceFactView::compose([(
        scope.clone(),
        ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
    )])
    .unwrap();
    let index =
        WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 48)])
            .unwrap();
    let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
    let mut policy = RecordingCallPolicy::default();

    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request("sniff-test.test.first-evidence", scope, root),
        &mut policy,
    )
    .unwrap();

    assert_eq!(prepared.callable_resolutions.len(), 1);
    assert_eq!(
        prepared.callable_resolutions[0].evidence_data.key(),
        &CallOccurrenceKey::new(root, 0)
    );
    let ProgramCompositionEdge::CallableInvocation { key, .. } =
        &prepared.callable_resolutions[0].edge
    else {
        panic!("the prepared witness must retain a callable resolution edge");
    };
    assert_eq!(*key, first_key);
    assert_eq!(policy.calls.len(), 2);
}

#[test]
fn repeated_evidence_for_one_key_and_callable_keeps_the_first_provenance() {
    let registry = registry();
    let scope = ArtifactScopeId::for_in_memory(49, 0);
    let root = FunctionKey::new(definition(49, 1), Some(instance(1)));
    let target = FunctionKey::new(definition(49, 2), Some(instance(2)));
    let key = CallableKey::FnPointer(type_hash(49));
    let mut artifact = ConfiguredCallArtifactBuilder::new(&registry, root);
    let callable = artifact
        .insert_target(target, TargetFixture::SeparateWithoutBody)
        .unwrap();
    let key_entity = artifact
        .builder
        .insert_entity(&CallableKeyEntity::new(key))
        .unwrap();
    for local_id in 0..2 {
        artifact.insert_keyed_call_for(
            root,
            local_id,
            CallKind::FnPointerReify,
            vec![CallAttributionRole::ErasureSite],
            &key_entity,
            &[(CallTargetRole::Runtime, callable.clone())],
        );
    }
    artifact.insert_keyed_call_for(
        root,
        2,
        CallKind::IndirectCall,
        vec![CallAttributionRole::CallSite],
        &key_entity,
        &[],
    );
    let artifact = artifact.finish(&registry);
    let workspace = WorkspaceFactView::compose([(
        scope.clone(),
        ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
    )])
    .unwrap();
    let index =
        WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 49)])
            .unwrap();
    let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request("sniff-test.test.repeat-evidence", scope, root),
        &mut ExpandPolicy,
    )
    .unwrap();

    assert_eq!(prepared.callable_resolutions.len(), 1);
    assert_eq!(
        prepared.callable_resolutions[0].evidence_data.key(),
        &CallOccurrenceKey::new(root, 0)
    );
}

#[test]
fn dyn_object_cast_with_a_callable_key_is_ignored_before_invocation_resolution() {
    let registry = registry();
    let scope = ArtifactScopeId::for_in_memory(10, 0);
    let root = FunctionKey::new(definition(10, 1), Some(instance(1)));
    let unused_target = FunctionKey::new(definition(10, 2), Some(instance(2)));
    let artifact = configured_call_artifact(
        &registry,
        root,
        unused_target,
        &ConfiguredCall {
            kind: CallKind::DynObjectCast,
            attribution: vec![CallAttributionRole::CallSite],
            callable_key: Some(CallableKey::DynDispatch(definition(10, 3))),
            target: TargetFixture::None,
            call_count: 1,
            route: CallRoute::Site,
            marker: None,
        },
    );
    let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
    let workspace = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
    let index =
        WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 10)])
            .unwrap();
    let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
    let request = RootProgramTraversalRequest::new(
        DomainId::new("sniff-test.test.dyn-cast").unwrap(),
        scope,
        root,
        CallAttributionRole::CallSite,
        MarkerProbe::SourceCallsite,
        8,
    );

    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request,
        &mut ExpandPolicy,
    )
    .unwrap();

    assert_eq!(prepared.occurrence_visits.len(), 1);
    assert!(
        prepared
            .outcomes
            .iter()
            .any(|outcome| outcome.kind == TraversalOutcomeKind::Ignored)
    );
}

struct ExternalAuthorityFixture {
    defining_scope: ArtifactScopeId,
    root: FunctionKey,
    external: FunctionKey,
    caller_artifact: ArtifactFactIr,
    missing_artifact: ArtifactFactIr,
    present_artifact: ArtifactFactIr,
}

fn external_authority_fixture(
    registry: &AnalysisRegistry<CollectedArtifact>,
) -> ExternalAuthorityFixture {
    let defining_scope = ArtifactScopeId::for_in_memory(21, 0);
    let root = FunctionKey::new(definition(20, 1), Some(instance(1)));
    let external = FunctionKey::new(definition(21, 2), Some(instance(2)));
    let caller_artifact = configured_call_artifact(
        registry,
        root,
        external,
        &ConfiguredCall {
            kind: CallKind::DirectCall,
            attribution: vec![CallAttributionRole::CallSite],
            callable_key: None,
            target: TargetFixture::SeparateWithoutBody,
            call_count: 1,
            route: CallRoute::Site,
            marker: None,
        },
    );
    let missing_artifact = root_artifact(registry, &[]);
    let present_artifact = root_artifact(
        registry,
        &[(external, FunctionBodyProvenance::DefiningArtifact)],
    );
    ExternalAuthorityFixture {
        defining_scope,
        root,
        external,
        caller_artifact,
        missing_artifact,
        present_artifact,
    }
}

struct ExternalAuthorityRun {
    root_scope: ArtifactScopeId,
    target_callable: ScopedEntityRef,
    traversal: ResolvedRootProgramTraversal<&'static str>,
}

fn resolve_external_authority_case(
    registry: &AnalysisRegistry<CollectedArtifact>,
    fixture: &ExternalAuthorityFixture,
    scope_ordinal: u32,
    dependency: &ArtifactFactIr,
    resolution: StableCrateResolution,
) -> ExternalAuthorityRun {
    let root_scope = ArtifactScopeId::for_in_memory(20, scope_ordinal);
    let root_view = ArtifactDbView::open(&fixture.caller_artifact, registry.schemas()).unwrap();
    let dependency_view = ArtifactDbView::open(dependency, registry.schemas()).unwrap();
    let workspace = WorkspaceFactView::compose([
        (root_scope.clone(), root_view),
        (fixture.defining_scope.clone(), dependency_view),
    ])
    .unwrap();
    let index = WorkspaceProgramIndex::open(
        &workspace,
        [
            VerifiedArtifactOwner::new(root_scope.clone(), 20),
            VerifiedArtifactOwner::new(fixture.defining_scope.clone(), 21),
        ],
    )
    .unwrap();
    let authority = VerifiedDefiningScopeMap::new(
        &workspace,
        &index,
        [DefiningScopeAuthority::new(
            root_scope.clone(),
            21,
            resolution,
        )],
    )
    .unwrap();
    let target_callable = index
        .exact_callable(&root_scope, &fixture.external)
        .expect("external callable exists in the caller artifact")
        .id()
        .erase();
    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request(
            "sniff-test.test.external-authority",
            root_scope.clone(),
            fixture.root,
        ),
        &mut FollowRuntimePolicy,
    )
    .unwrap();
    let traversal = resolve_prepared(prepared, &workspace, registry);
    ExternalAuthorityRun {
        root_scope,
        target_callable,
        traversal,
    }
}

#[test]
fn external_unmanaged_runtime_ends_at_the_exact_callable() {
    let registry = registry();
    let fixture = external_authority_fixture(&registry);
    let run = resolve_external_authority_case(
        &registry,
        &fixture,
        0,
        &fixture.missing_artifact,
        StableCrateResolution::Unmanaged,
    );

    let [outcome] = run.traversal.outcomes() else {
        panic!("unmanaged runtime produces one terminal outcome");
    };
    assert!(matches!(
        outcome.kind(),
        TraversalOutcomeKind::UnmanagedStableCrate {
            preferred_scope,
            stable_crate_id: 21,
            requested,
        } if preferred_scope == &run.root_scope && *requested == fixture.external
    ));
    assert_eq!(outcome.trace().target(), &run.target_callable);
}

#[test]
fn external_managed_runtime_missing_body_retains_both_generations() {
    let registry = registry();
    let fixture = external_authority_fixture(&registry);
    let run = resolve_external_authority_case(
        &registry,
        &fixture,
        1,
        &fixture.missing_artifact,
        StableCrateResolution::Managed(fixture.defining_scope.clone()),
    );

    let [outcome] = run.traversal.outcomes() else {
        panic!("managed runtime without a body produces one terminal outcome");
    };
    let [followed] = run.traversal.followed_calls() else {
        panic!("the accepted follow remains visible before body resolution fails");
    };
    assert!(matches!(
        outcome.kind(),
        TraversalOutcomeKind::MissingManagedBody {
            preferred_scope,
            defining_scope,
            stable_crate_id: 21,
            requested,
        } if preferred_scope == &run.root_scope
            && defining_scope == &fixture.defining_scope
            && *requested == fixture.external
    ));
    assert!(followed.order() < outcome.order());
    assert_eq!(followed.target().callable().erase(), run.target_callable);
    assert_eq!(followed.trace().target(), &run.target_callable);
    assert_eq!(outcome.trace().target(), &run.target_callable);
}

#[test]
fn external_managed_runtime_selects_only_the_exact_dependency_generation() {
    let registry = registry();
    let fixture = external_authority_fixture(&registry);
    let run = resolve_external_authority_case(
        &registry,
        &fixture,
        2,
        &fixture.present_artifact,
        StableCrateResolution::Managed(fixture.defining_scope.clone()),
    );

    assert!(run.traversal.outcomes().is_empty());
    let selected = run
        .traversal
        .body_visits()
        .iter()
        .find(|visit| visit.function() == fixture.external)
        .expect("managed exact body is reached");
    assert_eq!(selected.body().scope(), &fixture.defining_scope);
    assert_eq!(selected.trace().target(), &selected.body().erase());
    assert_eq!(
        selected
            .trace()
            .relations()
            .last()
            .map(|relation| relation.schema().as_str()),
        Some(CallableSelectsFunctionBody::ID)
    );
}

#[allow(
    clippy::too_many_arguments,
    reason = "the resolver fixture keeps each independently varied authority input explicit"
)]
fn resolved_presentation_scope(
    registry: &AnalysisRegistry<CollectedArtifact>,
    preferred_scope: &ArtifactScopeId,
    preferred_stable_crate_id: u64,
    preferred_artifact: &ArtifactFactIr,
    defining_scope: ArtifactScopeId,
    defining_stable_crate_id: u64,
    defining_artifact: &ArtifactFactIr,
    requested: FunctionKey,
    resolution: Option<StableCrateResolution>,
) -> ArtifactScopeId {
    let workspace = WorkspaceFactView::compose([
        (
            preferred_scope.clone(),
            ArtifactDbView::open(preferred_artifact, registry.schemas()).unwrap(),
        ),
        (
            defining_scope.clone(),
            ArtifactDbView::open(defining_artifact, registry.schemas()).unwrap(),
        ),
    ])
    .unwrap();
    let index = WorkspaceProgramIndex::open(
        &workspace,
        [
            VerifiedArtifactOwner::new(preferred_scope.clone(), preferred_stable_crate_id),
            VerifiedArtifactOwner::new(defining_scope, defining_stable_crate_id),
        ],
    )
    .unwrap();
    let authority = VerifiedDefiningScopeMap::new(
        &workspace,
        &index,
        resolution.into_iter().map(|resolution| {
            DefiningScopeAuthority::new(
                preferred_scope.clone(),
                requested.definition().stable_crate_id(),
                resolution,
            )
        }),
    )
    .unwrap();
    let resolver = authority
        .presentation_function_scopes(&workspace, &index)
        .unwrap();
    resolver.resolve(preferred_scope, &requested).unwrap()
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one table-style test pins every presentation-scope precedence and fallback branch"
)]
fn presentation_scope_resolution_preserves_every_legacy_fallback_branch() {
    let registry = registry();
    let requested = FunctionKey::new(definition(21, 7), Some(instance(7)));
    let generic = FunctionKey::new(requested.definition(), None);
    let empty = root_artifact(&registry, &[]);
    let exact_defining = root_artifact(
        &registry,
        &[(requested, FunctionBodyProvenance::DefiningArtifact)],
    );
    let generic_defining = root_artifact(
        &registry,
        &[(generic, FunctionBodyProvenance::DefiningArtifact)],
    );
    let defining_scope = ArtifactScopeId::for_in_memory(21, 70);
    let preferred =
        |stable_crate_id, ordinal| ArtifactScopeId::for_in_memory(stable_crate_id, ordinal);
    let resolve = |preferred_scope: ArtifactScopeId,
                   preferred_stable_crate_id,
                   preferred_artifact: &ArtifactFactIr,
                   defining_artifact: &ArtifactFactIr,
                   resolution| {
        resolved_presentation_scope(
            &registry,
            &preferred_scope,
            preferred_stable_crate_id,
            preferred_artifact,
            defining_scope.clone(),
            21,
            defining_artifact,
            requested,
            resolution,
        )
    };

    for defining_artifact in [&exact_defining, &generic_defining] {
        assert_eq!(
            resolve(
                preferred(20, 0),
                20,
                &empty,
                defining_artifact,
                Some(StableCrateResolution::Managed(defining_scope.clone())),
            ),
            defining_scope
        );
    }
    for (defining_artifact, resolution) in [
        (&exact_defining, Some(StableCrateResolution::Unmanaged)),
        (
            &empty,
            Some(StableCrateResolution::Managed(defining_scope.clone())),
        ),
        (&exact_defining, None),
    ] {
        let caller = preferred(20, 1);
        assert_eq!(
            resolve(caller.clone(), 20, &empty, defining_artifact, resolution,),
            caller
        );
    }

    let local_exact = root_artifact(
        &registry,
        &[(
            requested,
            FunctionBodyProvenance::ConsumerInstantiation {
                consumer_stable_crate_id: 20,
            },
        )],
    );
    let exact_caller = preferred(20, 2);
    assert_eq!(
        resolve(
            exact_caller.clone(),
            20,
            &local_exact,
            &exact_defining,
            Some(StableCrateResolution::Managed(defining_scope.clone())),
        ),
        exact_caller
    );

    let local_generic = root_artifact(
        &registry,
        &[(generic, FunctionBodyProvenance::DefiningArtifact)],
    );
    let generic_caller = preferred(21, 3);
    assert_eq!(
        resolve(generic_caller.clone(), 21, &local_generic, &empty, None,),
        generic_caller
    );

    let second_local_exact = root_artifact(
        &registry,
        &[(
            requested,
            FunctionBodyProvenance::ConsumerInstantiation {
                consumer_stable_crate_id: 22,
            },
        )],
    );
    let first_scope = preferred(20, 4);
    let second_scope = preferred(22, 4);
    let first = resolve(
        first_scope.clone(),
        20,
        &local_exact,
        &exact_defining,
        Some(StableCrateResolution::Managed(defining_scope.clone())),
    );
    let second = resolve(
        second_scope.clone(),
        22,
        &second_local_exact,
        &exact_defining,
        Some(StableCrateResolution::Managed(defining_scope.clone())),
    );

    assert_eq!(first, first_scope);
    assert_eq!(second, second_scope);
    assert_ne!(first, second);
}

#[test]
fn invalid_policy_target_selection_is_rejected() {
    let registry = registry();
    let scope = ArtifactScopeId::for_in_memory(22, 0);
    let root = FunctionKey::new(definition(22, 1), Some(instance(1)));
    let target = FunctionKey::new(definition(22, 2), Some(instance(2)));
    let artifact = direct_call_artifact(&registry, root, target);
    let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
    let workspace = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
    let index =
        WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 22)])
            .unwrap();
    let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
    let invalid = index
        .exact_callable(&scope, &root)
        .expect("root callable exists")
        .id();

    let result = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request("sniff-test.test.invalid-policy", scope, root),
        &mut InvalidSelectionPolicy { target: invalid },
    );

    assert!(matches!(
        result,
        Err(RootProgramTraversalError::InvalidPolicyDecision { .. })
    ));
}

struct ConsumerSourceFixture {
    defining_scope: ArtifactScopeId,
    consumer: FunctionKey,
    generic: FunctionKey,
    consumer_artifact: ArtifactFactIr,
    missing_artifact: ArtifactFactIr,
    present_artifact: ArtifactFactIr,
}

fn consumer_source_fixture(
    registry: &AnalysisRegistry<CollectedArtifact>,
) -> ConsumerSourceFixture {
    let defining_scope = ArtifactScopeId::for_in_memory(31, 0);
    let consumer = FunctionKey::new(definition(31, 1), Some(instance(1)));
    let generic = FunctionKey::new(consumer.definition(), None);
    let consumer_artifact = root_artifact(
        registry,
        &[(
            consumer,
            FunctionBodyProvenance::ConsumerInstantiation {
                consumer_stable_crate_id: 30,
            },
        )],
    );
    let missing_artifact = root_artifact(registry, &[]);
    let present_artifact = root_artifact(
        registry,
        &[(generic, FunctionBodyProvenance::DefiningArtifact)],
    );
    ConsumerSourceFixture {
        defining_scope,
        consumer,
        generic,
        consumer_artifact,
        missing_artifact,
        present_artifact,
    }
}

struct ConsumerSourceRun {
    consumer_scope: ArtifactScopeId,
    traversal: ResolvedRootProgramTraversal<&'static str>,
}

fn resolve_consumer_source_case(
    registry: &AnalysisRegistry<CollectedArtifact>,
    fixture: &ConsumerSourceFixture,
    scope_ordinal: u32,
    dependency: &ArtifactFactIr,
    resolution: StableCrateResolution,
) -> ConsumerSourceRun {
    let consumer_scope = ArtifactScopeId::for_in_memory(30, scope_ordinal);
    let consumer_view =
        ArtifactDbView::open(&fixture.consumer_artifact, registry.schemas()).unwrap();
    let dependency_view = ArtifactDbView::open(dependency, registry.schemas()).unwrap();
    let workspace = WorkspaceFactView::compose([
        (consumer_scope.clone(), consumer_view),
        (fixture.defining_scope.clone(), dependency_view),
    ])
    .unwrap();
    let index = WorkspaceProgramIndex::open(
        &workspace,
        [
            VerifiedArtifactOwner::new(consumer_scope.clone(), 30),
            VerifiedArtifactOwner::new(fixture.defining_scope.clone(), 31),
        ],
    )
    .unwrap();
    let authority = VerifiedDefiningScopeMap::new(
        &workspace,
        &index,
        [DefiningScopeAuthority::new(
            consumer_scope.clone(),
            31,
            resolution,
        )],
    )
    .unwrap();
    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request(
            "sniff-test.test.consumer-source",
            consumer_scope.clone(),
            fixture.consumer,
        ),
        &mut ExpandPolicy,
    )
    .unwrap();
    let traversal = resolve_prepared(prepared, &workspace, registry);
    ConsumerSourceRun {
        consumer_scope,
        traversal,
    }
}

fn assert_consumer_mir_is_the_only_runtime_body(run: &ConsumerSourceRun, consumer: FunctionKey) {
    let [visit] = run.traversal.body_visits() else {
        panic!("consumer MIR remains the only traversed runtime body");
    };
    assert_eq!(visit.function(), consumer);
    assert_eq!(visit.body().scope(), &run.consumer_scope);
}

#[test]
fn unmanaged_consumer_defining_source_is_a_generation_aware_source_gap() {
    let registry = registry();
    let fixture = consumer_source_fixture(&registry);
    let run = resolve_consumer_source_case(
        &registry,
        &fixture,
        0,
        &fixture.missing_artifact,
        StableCrateResolution::Unmanaged,
    );

    assert_consumer_mir_is_the_only_runtime_body(&run, fixture.consumer);
    assert!(matches!(
        run.traversal.outcomes(),
        [outcome] if matches!(
            outcome.kind(),
            TraversalOutcomeKind::UnmanagedDefiningSource {
                preferred_scope,
                stable_crate_id: 31,
                consumer,
            } if preferred_scope == &run.consumer_scope && *consumer == fixture.consumer
        )
    ));
}

#[test]
fn managed_consumer_defining_source_missing_body_retains_both_generations() {
    let registry = registry();
    let fixture = consumer_source_fixture(&registry);
    let run = resolve_consumer_source_case(
        &registry,
        &fixture,
        1,
        &fixture.missing_artifact,
        StableCrateResolution::Managed(fixture.defining_scope.clone()),
    );

    assert_consumer_mir_is_the_only_runtime_body(&run, fixture.consumer);
    assert!(matches!(
        run.traversal.outcomes(),
        [outcome] if matches!(
            outcome.kind(),
            TraversalOutcomeKind::MissingManagedDefiningSource {
                preferred_scope,
                defining_scope,
                stable_crate_id: 31,
                consumer,
            } if preferred_scope == &run.consumer_scope
                && defining_scope == &fixture.defining_scope
                && *consumer == fixture.consumer
        )
    ));
}

#[test]
fn managed_consumer_source_emits_exact_generic_side_edge_without_traversing_it() {
    let registry = registry();
    let fixture = consumer_source_fixture(&registry);
    let run = resolve_consumer_source_case(
        &registry,
        &fixture,
        2,
        &fixture.present_artifact,
        StableCrateResolution::Managed(fixture.defining_scope.clone()),
    );

    assert_consumer_mir_is_the_only_runtime_body(&run, fixture.consumer);
    assert!(run.traversal.outcomes().is_empty());
    let [source] = run.traversal.consumer_body_sources() else {
        panic!("one consumer-source witness is resolved");
    };
    assert_eq!(source.consumer().scope(), &run.consumer_scope);
    assert_eq!(source.defining().scope(), &fixture.defining_scope);
    assert_eq!(*source.consumer_data().key(), fixture.consumer);
    assert_eq!(*source.defining_data().key(), fixture.generic);
    assert_eq!(
        source.selection(),
        CallableBodySelectionKind::GenericDefining
    );
    assert_eq!(source.trace().target(), &source.defining().erase());
    assert_eq!(
        source
            .trace()
            .relations()
            .last()
            .map(|relation| relation.schema().as_str()),
        Some(ConsumerOverlayUsesDefiningSourceBody::ID)
    );
}

#[test]
fn consumer_visits_local_then_defining_unsafe_operations_before_calls() {
    let registry = registry();
    let consumer_scope = ArtifactScopeId::for_in_memory(31, 20);
    let defining_scope = ArtifactScopeId::for_in_memory(32, 20);
    let consumer = FunctionKey::new(definition(32, 20), Some(instance(20)));
    let defining = FunctionKey::new(consumer.definition(), None);
    let domain = "sniff-test.test.consumer-unsafe-operations";

    let mut consumer_builder = ConfiguredCallArtifactBuilder::new_with_provenance(
        &registry,
        consumer,
        FunctionBodyProvenance::ConsumerInstantiation {
            consumer_stable_crate_id: 31,
        },
    );
    consumer_builder.insert_unsafe_operation(consumer, 0, SafetyOperationKind::DerefRawPointer);
    consumer_builder.insert_call_for(consumer, 0, None);
    let consumer_artifact = consumer_builder.finish(&registry);

    let mut defining_builder = ConfiguredCallArtifactBuilder::new(&registry, defining);
    let defining_operation =
        defining_builder.insert_unsafe_operation(defining, 0, SafetyOperationKind::InlineAssembly);
    let defining_claim = defining_builder.attach_unsafe_operation_marker(
        &defining_operation,
        domain,
        MarkerMatch::SourceCallsite,
    );
    let defining_artifact = defining_builder.finish(&registry);
    let workspace = WorkspaceFactView::compose([
        (
            consumer_scope.clone(),
            ArtifactDbView::open(&consumer_artifact, registry.schemas()).unwrap(),
        ),
        (
            defining_scope.clone(),
            ArtifactDbView::open(&defining_artifact, registry.schemas()).unwrap(),
        ),
    ])
    .unwrap();
    let index = WorkspaceProgramIndex::open(
        &workspace,
        [
            VerifiedArtifactOwner::new(consumer_scope.clone(), 31),
            VerifiedArtifactOwner::new(defining_scope.clone(), 32),
        ],
    )
    .unwrap();
    let authority = VerifiedDefiningScopeMap::new(
        &workspace,
        &index,
        [DefiningScopeAuthority::new(
            consumer_scope.clone(),
            32,
            StableCrateResolution::Managed(defining_scope.clone()),
        )],
    )
    .unwrap();
    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request(domain, consumer_scope.clone(), consumer),
        &mut ExpandPolicy,
    )
    .unwrap();
    let traversal = resolve_prepared(prepared, &workspace, &registry);

    let [local, defining_visit] = traversal.unsafe_operation_visits() else {
        panic!("consumer traversal visits local and defining operations")
    };
    assert_eq!(local.owner().scope(), &consumer_scope);
    assert_eq!(defining_visit.owner().scope(), &defining_scope);
    assert!(local.order() < defining_visit.order());
    assert!(defining_visit.order() < traversal.occurrence_visits()[0].order());
    assert_eq!(
        defining_visit.attached_marker_candidates()[0].claim(),
        &index
            .exact_marker_claim(&defining_scope, defining_claim.key())
            .unwrap()
            .id()
    );
    assert_eq!(
        defining_visit
            .trace()
            .relations()
            .iter()
            .map(|relation| relation.schema().as_str())
            .collect::<Vec<_>>(),
        vec![
            ConsumerOverlayUsesDefiningSourceBody::ID,
            FunctionOwnsUnsafeOperation::ID,
        ]
    );
}

#[test]
fn consumer_and_defining_calls_emit_exact_semantic_reconciliation() {
    let registry = registry();
    let consumer_scope = ArtifactScopeId::for_in_memory(40, 0);
    let defining_scope = ArtifactScopeId::for_in_memory(41, 0);
    let consumer = FunctionKey::new(definition(41, 1), Some(instance(1)));
    let defining = FunctionKey::new(consumer.definition(), None);
    let call = ConfiguredCall {
        kind: CallKind::DirectCall,
        attribution: vec![CallAttributionRole::CallSite],
        callable_key: None,
        target: TargetFixture::None,
        call_count: 1,
        route: CallRoute::Site,
        marker: None,
    };

    let mut consumer_builder = ConfiguredCallArtifactBuilder::new_with_provenance(
        &registry,
        consumer,
        FunctionBodyProvenance::ConsumerInstantiation {
            consumer_stable_crate_id: 40,
        },
    );
    let consumer_occurrence = consumer_builder.insert_calls(&call, None).unwrap();
    consumer_builder
        .attach_call_source_anchor(&consumer_occurrence, CallSourceAnchorRole::Expanded);
    let consumer_artifact = consumer_builder.finish(&registry);

    let mut defining_builder = ConfiguredCallArtifactBuilder::new(&registry, defining);
    let defining_occurrence = defining_builder.insert_calls(&call, None).unwrap();
    defining_builder
        .attach_call_source_anchor(&defining_occurrence, CallSourceAnchorRole::Expanded);
    let defining_artifact = defining_builder.finish(&registry);

    let workspace = WorkspaceFactView::compose([
        (
            consumer_scope.clone(),
            ArtifactDbView::open(&consumer_artifact, registry.schemas()).unwrap(),
        ),
        (
            defining_scope.clone(),
            ArtifactDbView::open(&defining_artifact, registry.schemas()).unwrap(),
        ),
    ])
    .unwrap();
    let index = WorkspaceProgramIndex::open(
        &workspace,
        [
            VerifiedArtifactOwner::new(consumer_scope.clone(), 40),
            VerifiedArtifactOwner::new(defining_scope.clone(), 41),
        ],
    )
    .unwrap();
    let authority = VerifiedDefiningScopeMap::new(
        &workspace,
        &index,
        [DefiningScopeAuthority::new(
            consumer_scope.clone(),
            41,
            StableCrateResolution::Managed(defining_scope.clone()),
        )],
    )
    .unwrap();

    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request(
            "sniff-test.test.consumer-reconciliation",
            consumer_scope.clone(),
            consumer,
        ),
        &mut ExpandPolicy,
    )
    .unwrap();
    let traversal = resolve_prepared(prepared, &workspace, &registry);
    assert_exact_semantic_reconciliation(&traversal, &consumer_scope, &defining_scope);
}

fn assert_exact_semantic_reconciliation(
    traversal: &ResolvedRootProgramTraversal<&'static str>,
    consumer_scope: &ArtifactScopeId,
    defining_scope: &ArtifactScopeId,
) {
    let [reconciliation] = traversal.consumer_reconciliations() else {
        panic!("one exact consumer/defining occurrence reconciliation is resolved");
    };
    let [occurrence] = traversal.occurrence_visits() else {
        panic!("one consumer occurrence is visited");
    };
    assert!(occurrence.order() < reconciliation.order());
    assert_eq!(
        reconciliation.kind(),
        ConsumerOccurrenceReconciliationKind::SemanticTarget
    );
    assert_eq!(reconciliation.consumer().scope(), consumer_scope);
    assert_eq!(reconciliation.defining().scope(), defining_scope);
    assert_eq!(
        reconciliation
            .trace()
            .relations()
            .last()
            .map(|relation| relation.schema().as_str()),
        Some(ConsumerOccurrenceReconcilesWith::ID)
    );
    assert_eq!(
        reconciliation
            .trace()
            .relations()
            .iter()
            .map(|relation| relation.schema().as_str())
            .collect::<Vec<_>>(),
        vec![
            FunctionOwnsCallSite::ID,
            CallSiteHasOccurrence::ID,
            ConsumerOccurrenceReconcilesWith::ID,
        ]
    );
}

#[test]
fn semantic_matches_suppress_source_fallback_candidates() {
    let registry = registry();
    let consumer_scope = ArtifactScopeId::for_in_memory(50, 0);
    let defining_scope = ArtifactScopeId::for_in_memory(51, 0);
    let consumer = FunctionKey::new(definition(51, 1), Some(instance(1)));
    let defining = FunctionKey::new(consumer.definition(), None);
    let semantic_target = FunctionKey::new(definition(60, 1), Some(instance(1)));
    let fallback_target = FunctionKey::new(definition(60, 2), Some(instance(2)));

    let mut consumer_builder = ConfiguredCallArtifactBuilder::new_with_provenance(
        &registry,
        consumer,
        FunctionBodyProvenance::ConsumerInstantiation {
            consumer_stable_crate_id: 50,
        },
    );
    let consumer_target = consumer_builder
        .insert_target(semantic_target, TargetFixture::SeparateWithoutBody)
        .unwrap();
    let consumer_occurrence = consumer_builder.insert_call_for(consumer, 0, Some(&consumer_target));
    consumer_builder
        .attach_call_source_anchor(&consumer_occurrence, CallSourceAnchorRole::Expanded);
    let consumer_artifact = consumer_builder.finish(&registry);

    let mut defining_builder = ConfiguredCallArtifactBuilder::new(&registry, defining);
    let exact_target = defining_builder
        .insert_target(semantic_target, TargetFixture::SeparateWithoutBody)
        .unwrap();
    let other_target = defining_builder
        .insert_target(fallback_target, TargetFixture::SeparateWithoutBody)
        .unwrap();
    let semantic = defining_builder.insert_call_for(defining, 0, Some(&exact_target));
    let fallback = defining_builder.insert_call_for(defining, 1, Some(&other_target));
    defining_builder.attach_call_source_anchor(&semantic, CallSourceAnchorRole::Expanded);
    defining_builder.attach_call_source_anchor(&fallback, CallSourceAnchorRole::Expanded);
    let defining_artifact = defining_builder.finish(&registry);

    let workspace = WorkspaceFactView::compose([
        (
            consumer_scope.clone(),
            ArtifactDbView::open(&consumer_artifact, registry.schemas()).unwrap(),
        ),
        (
            defining_scope.clone(),
            ArtifactDbView::open(&defining_artifact, registry.schemas()).unwrap(),
        ),
    ])
    .unwrap();
    let index = WorkspaceProgramIndex::open(
        &workspace,
        [
            VerifiedArtifactOwner::new(consumer_scope.clone(), 50),
            VerifiedArtifactOwner::new(defining_scope.clone(), 51),
        ],
    )
    .unwrap();
    let authority = VerifiedDefiningScopeMap::new(
        &workspace,
        &index,
        [DefiningScopeAuthority::new(
            consumer_scope.clone(),
            51,
            StableCrateResolution::Managed(defining_scope.clone()),
        )],
    )
    .unwrap();
    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request(
            "sniff-test.test.semantic-suppresses-fallback",
            consumer_scope,
            consumer,
        ),
        &mut ExpandPolicy,
    )
    .unwrap();

    let [reconciliation] = prepared.consumer_reconciliations.as_slice() else {
        panic!("only the semantic defining occurrence is selected");
    };
    assert_eq!(reconciliation.defining_data.key(), semantic.key());
    assert_eq!(
        reconciliation.kind,
        ConsumerOccurrenceReconciliationKind::SemanticTarget
    );
}

#[test]
fn source_fallback_requires_actual_calls_on_both_sides() {
    let registry = registry();
    for (generation, defining_kind, expected) in [
        (0, CallKind::TailCall, true),
        (1, CallKind::ConstBody, false),
    ] {
        let consumer_scope = ArtifactScopeId::for_in_memory(52, generation);
        let defining_scope = ArtifactScopeId::for_in_memory(53, generation);
        let consumer = FunctionKey::new(definition(53, 1), Some(instance(1)));
        let defining = FunctionKey::new(consumer.definition(), None);
        let consumer_call = ConfiguredCall {
            kind: CallKind::DirectCall,
            attribution: vec![CallAttributionRole::CallSite],
            callable_key: None,
            target: TargetFixture::None,
            call_count: 1,
            route: CallRoute::Site,
            marker: None,
        };
        let defining_call = ConfiguredCall {
            kind: defining_kind,
            attribution: vec![CallAttributionRole::CallSite],
            callable_key: None,
            target: TargetFixture::None,
            call_count: 1,
            route: CallRoute::Site,
            marker: None,
        };
        let mut consumer_builder = ConfiguredCallArtifactBuilder::new_with_provenance(
            &registry,
            consumer,
            FunctionBodyProvenance::ConsumerInstantiation {
                consumer_stable_crate_id: 52,
            },
        );
        let consumer_occurrence = consumer_builder.insert_calls(&consumer_call, None).unwrap();
        consumer_builder
            .attach_call_source_anchor(&consumer_occurrence, CallSourceAnchorRole::Expanded);
        let consumer_artifact = consumer_builder.finish(&registry);
        let mut defining_builder = ConfiguredCallArtifactBuilder::new(&registry, defining);
        let defining_occurrence = defining_builder.insert_calls(&defining_call, None).unwrap();
        defining_builder
            .attach_call_source_anchor(&defining_occurrence, CallSourceAnchorRole::Expanded);
        let defining_artifact = defining_builder.finish(&registry);
        let workspace = WorkspaceFactView::compose([
            (
                consumer_scope.clone(),
                ArtifactDbView::open(&consumer_artifact, registry.schemas()).unwrap(),
            ),
            (
                defining_scope.clone(),
                ArtifactDbView::open(&defining_artifact, registry.schemas()).unwrap(),
            ),
        ])
        .unwrap();
        let index = WorkspaceProgramIndex::open(
            &workspace,
            [
                VerifiedArtifactOwner::new(consumer_scope.clone(), 52),
                VerifiedArtifactOwner::new(defining_scope.clone(), 53),
            ],
        )
        .unwrap();
        let authority = VerifiedDefiningScopeMap::new(
            &workspace,
            &index,
            [DefiningScopeAuthority::new(
                consumer_scope.clone(),
                53,
                StableCrateResolution::Managed(defining_scope),
            )],
        )
        .unwrap();
        let prepared = PreparedRootProgramTraversal::prepare(
            &workspace,
            &index,
            &authority,
            &request(
                "sniff-test.test.actual-call-fallback",
                consumer_scope,
                consumer,
            ),
            &mut ExpandPolicy,
        )
        .unwrap();
        assert_eq!(
            prepared.consumer_reconciliations.len(),
            usize::from(expected)
        );
        if expected {
            assert_eq!(
                prepared.consumer_reconciliations[0].kind,
                ConsumerOccurrenceReconciliationKind::SourceFallback
            );
        }
    }
}

fn indexed_semantic_reconciliation_artifacts(
    registry: &AnalysisRegistry<CollectedArtifact>,
    call_count: u32,
) -> (ArtifactFactIr, ArtifactFactIr, FunctionKey) {
    let consumer = FunctionKey::new(definition(57, 1), Some(instance(1)));
    let defining = FunctionKey::new(consumer.definition(), None);
    let mut consumer_builder = ConfiguredCallArtifactBuilder::new_with_provenance(
        registry,
        consumer,
        FunctionBodyProvenance::ConsumerInstantiation {
            consumer_stable_crate_id: 56,
        },
    );
    let mut defining_builder = ConfiguredCallArtifactBuilder::new(registry, defining);
    for local_id in 0..call_count {
        let target = FunctionKey::new(
            definition(58, u64::from(local_id) + 1),
            Some(instance(u128::from(local_id) + 1)),
        );
        let consumer_target = consumer_builder
            .insert_target(target, TargetFixture::SeparateWithoutBody)
            .unwrap();
        let defining_target = defining_builder
            .insert_target(target, TargetFixture::SeparateWithoutBody)
            .unwrap();
        let consumer_call =
            consumer_builder.insert_call_for(consumer, local_id, Some(&consumer_target));
        let defining_call =
            defining_builder.insert_call_for(defining, local_id, Some(&defining_target));
        consumer_builder.attach_call_source_anchor(&consumer_call, CallSourceAnchorRole::Expanded);
        defining_builder.attach_call_source_anchor(&defining_call, CallSourceAnchorRole::Expanded);
    }
    (
        consumer_builder.finish(registry),
        defining_builder.finish(registry),
        consumer,
    )
}

#[test]
fn semantic_source_bucket_lookup_is_linear_in_index_input_plus_selected_output() {
    const CALLS: usize = 32;
    let registry = registry();
    let consumer_scope = ArtifactScopeId::for_in_memory(56, 0);
    let defining_scope = ArtifactScopeId::for_in_memory(57, 0);
    let (consumer_artifact, defining_artifact, consumer) =
        indexed_semantic_reconciliation_artifacts(&registry, u32::try_from(CALLS).unwrap());
    let workspace = WorkspaceFactView::compose([
        (
            consumer_scope.clone(),
            ArtifactDbView::open(&consumer_artifact, registry.schemas()).unwrap(),
        ),
        (
            defining_scope.clone(),
            ArtifactDbView::open(&defining_artifact, registry.schemas()).unwrap(),
        ),
    ])
    .unwrap();
    let index = WorkspaceProgramIndex::open(
        &workspace,
        [
            VerifiedArtifactOwner::new(consumer_scope.clone(), 56),
            VerifiedArtifactOwner::new(defining_scope.clone(), 57),
        ],
    )
    .unwrap();
    let authority = VerifiedDefiningScopeMap::new(
        &workspace,
        &index,
        [DefiningScopeAuthority::new(
            consumer_scope.clone(),
            57,
            StableCrateResolution::Managed(defining_scope.clone()),
        )],
    )
    .unwrap();
    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request(
            "sniff-test.test.indexed-reconciliation",
            consumer_scope,
            consumer,
        ),
        &mut ExpandPolicy,
    )
    .unwrap();

    assert_eq!(prepared.consumer_reconciliations.len(), CALLS);
    assert_eq!(
        prepared.consumer_reconciliation_metrics,
        ConsumerReconciliationMetrics {
            plans_built: 1,
            plan_cache_hits: 0,
            defining_routes_indexed: CALLS,
            source_bucket_lookups: CALLS,
            semantic_candidates_inspected: CALLS,
            unsafe_route_indexes_built: 2,
            unsafe_route_cache_hits: 0,
        }
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one cache regression verifies path-safe output across marker-state revisits"
)]
fn consumer_source_plan_is_reused_when_marker_state_revisits_the_same_body() {
    let registry = registry();
    let consumer_scope = ArtifactScopeId::for_in_memory(56, 1);
    let defining_scope = ArtifactScopeId::for_in_memory(57, 1);
    let consumer = FunctionKey::new(definition(57, 2), Some(instance(2)));
    let defining = FunctionKey::new(consumer.definition(), None);
    let domain = "sniff-test.test.consumer-plan-cache";
    let mut consumer_builder = ConfiguredCallArtifactBuilder::new_with_provenance(
        &registry,
        consumer,
        FunctionBodyProvenance::ConsumerInstantiation {
            consumer_stable_crate_id: 56,
        },
    );
    let recursive_target = consumer_builder.root_callable.clone();
    let consumer_call = consumer_builder.insert_call_for(consumer, 0, Some(&recursive_target));
    consumer_builder.insert_unsafe_operation(consumer, 0, SafetyOperationKind::DerefRawPointer);
    consumer_builder.attach_call_source_anchor(&consumer_call, CallSourceAnchorRole::Expanded);
    consumer_builder.insert_marker(
        MarkerEndpoint::Call,
        domain,
        MarkerMatch::SourceCallsite,
        Some(&consumer_call),
    );
    let consumer_artifact = consumer_builder.finish(&registry);
    let mut defining_builder = ConfiguredCallArtifactBuilder::new(&registry, defining);
    let defining_call = defining_builder.insert_call_for(defining, 0, None);
    let defining_operation =
        defining_builder.insert_unsafe_operation(defining, 0, SafetyOperationKind::InlineAssembly);
    defining_builder.attach_unsafe_operation_marker(
        &defining_operation,
        domain,
        MarkerMatch::SourceCallsite,
    );
    defining_builder.attach_call_source_anchor(&defining_call, CallSourceAnchorRole::Expanded);
    let defining_artifact = defining_builder.finish(&registry);
    let workspace = WorkspaceFactView::compose([
        (
            consumer_scope.clone(),
            ArtifactDbView::open(&consumer_artifact, registry.schemas()).unwrap(),
        ),
        (
            defining_scope.clone(),
            ArtifactDbView::open(&defining_artifact, registry.schemas()).unwrap(),
        ),
    ])
    .unwrap();
    let index = WorkspaceProgramIndex::open(
        &workspace,
        [
            VerifiedArtifactOwner::new(consumer_scope.clone(), 56),
            VerifiedArtifactOwner::new(defining_scope.clone(), 57),
        ],
    )
    .unwrap();
    let authority = VerifiedDefiningScopeMap::new(
        &workspace,
        &index,
        [DefiningScopeAuthority::new(
            consumer_scope.clone(),
            57,
            StableCrateResolution::Managed(defining_scope.clone()),
        )],
    )
    .unwrap();
    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request(domain, consumer_scope.clone(), consumer),
        &mut ObservingFollowPolicy::default(),
    )
    .unwrap();

    assert_eq!(prepared.body_visits.len(), 2);
    assert_eq!(prepared.consumer_body_sources.len(), 2);
    assert_eq!(prepared.consumer_reconciliation_metrics.plans_built, 1);
    assert_eq!(prepared.consumer_reconciliation_metrics.plan_cache_hits, 1);
    assert_eq!(prepared.unsafe_operation_visits.len(), 4);
    assert_eq!(
        prepared
            .consumer_reconciliation_metrics
            .unsafe_route_indexes_built,
        2
    );
    assert_eq!(
        prepared
            .consumer_reconciliation_metrics
            .unsafe_route_cache_hits,
        2
    );
    assert_eq!(
        prepared.unsafe_operation_visits[1]
            .attached_marker_candidates
            .0
            .len(),
        1
    );
    assert_eq!(
        prepared.unsafe_operation_visits[3]
            .inherited_markers
            .0
            .len(),
        1
    );
    assert_eq!(
        prepared.unsafe_operation_visits[3].active_markers.0.len(),
        2
    );
    assert_eq!(
        prepared
            .consumer_reconciliation_metrics
            .defining_routes_indexed,
        1
    );
    assert_eq!(
        prepared
            .consumer_reconciliation_metrics
            .source_bucket_lookups,
        2
    );
    let traversal = resolve_prepared(prepared, &workspace, &registry);
    let [first_local, first_defining, second_local, second_defining] =
        traversal.unsafe_operation_visits()
    else {
        panic!("both transported marker states visit local and defining operations")
    };
    assert_eq!(first_local.owner().scope(), &consumer_scope);
    assert_eq!(first_defining.owner().scope(), &defining_scope);
    assert_eq!(second_local.owner().scope(), &consumer_scope);
    assert_eq!(second_defining.owner().scope(), &defining_scope);
    assert_ne!(first_defining.trace(), second_defining.trace());
    assert_eq!(
        first_defining
            .trace()
            .relations()
            .iter()
            .map(|relation| relation.schema().as_str())
            .collect::<Vec<_>>(),
        vec![
            ConsumerOverlayUsesDefiningSourceBody::ID,
            FunctionOwnsUnsafeOperation::ID,
        ]
    );
    assert_eq!(
        &second_defining.trace().relations()[second_defining.trace().relations().len() - 2..]
            .iter()
            .map(|relation| relation.schema().as_str())
            .collect::<Vec<_>>(),
        &[
            ConsumerOverlayUsesDefiningSourceBody::ID,
            FunctionOwnsUnsafeOperation::ID,
        ]
    );
    assert_eq!(second_defining.inherited_markers().len(), 1);
    assert_eq!(second_defining.attached_marker_candidates().len(), 1);
    assert_eq!(second_defining.active_markers().len(), 2);
}

fn reconciliation_marker_consumer_artifact(
    registry: &AnalysisRegistry<CollectedArtifact>,
    consumer: FunctionKey,
) -> ArtifactFactIr {
    let key = CallableKey::FnPointer(type_hash(55));
    let mut consumer_builder = ConfiguredCallArtifactBuilder::new_with_provenance(
        registry,
        consumer,
        FunctionBodyProvenance::ConsumerInstantiation {
            consumer_stable_crate_id: 54,
        },
    );
    let evidence_target = consumer_builder
        .insert_target(
            FunctionKey::new(definition(54, 2), Some(instance(2))),
            TargetFixture::SeparateWithoutBody,
        )
        .unwrap();
    let callable_key = consumer_builder
        .builder
        .insert_entity(&CallableKeyEntity::new(key))
        .unwrap();
    let invocation = consumer_builder.insert_keyed_call_for(
        consumer,
        0,
        CallKind::IndirectCall,
        vec![CallAttributionRole::CallSite],
        &callable_key,
        &[],
    );
    consumer_builder.attach_call_source_anchor(&invocation, CallSourceAnchorRole::Expanded);
    consumer_builder.insert_keyed_call_for(
        consumer,
        1,
        CallKind::FnPointerReify,
        vec![CallAttributionRole::ErasureSite],
        &callable_key,
        &[(CallTargetRole::Runtime, evidence_target)],
    );
    consumer_builder.finish(registry)
}

fn reconciliation_marker_defining_artifact(
    registry: &AnalysisRegistry<CollectedArtifact>,
    defining: FunctionKey,
) -> ArtifactFactIr {
    let mut defining_builder = ConfiguredCallArtifactBuilder::new(registry, defining);
    let defining_calls = defining_builder.insert_calls_all(
        &ConfiguredCall {
            kind: CallKind::IndirectCall,
            attribution: vec![CallAttributionRole::CallSite],
            callable_key: None,
            target: TargetFixture::None,
            call_count: 2,
            route: CallRoute::Site,
            marker: None,
        },
        None,
    );
    for occurrence in &defining_calls {
        defining_builder.attach_call_source_anchor(occurrence, CallSourceAnchorRole::Expanded);
        defining_builder
            .insert_call_marker_claim(occurrence, "sniff-test.test.reconciliation-markers");
    }
    defining_builder.finish(registry)
}

fn run_reconciliation_marker_case(
    registry: &AnalysisRegistry<CollectedArtifact>,
    generation: u32,
    decision: DefiningMarkerDecision,
) -> (
    ReconciliationMarkerPolicy,
    ResolvedRootProgramTraversal<&'static str>,
) {
    let consumer_scope = ArtifactScopeId::for_in_memory(54, generation);
    let defining_scope = ArtifactScopeId::for_in_memory(55, generation);
    let consumer = FunctionKey::new(definition(55, 1), Some(instance(1)));
    let defining = FunctionKey::new(consumer.definition(), None);
    let consumer_artifact = reconciliation_marker_consumer_artifact(registry, consumer);
    let defining_artifact = reconciliation_marker_defining_artifact(registry, defining);
    let workspace = WorkspaceFactView::compose([
        (
            consumer_scope.clone(),
            ArtifactDbView::open(&consumer_artifact, registry.schemas()).unwrap(),
        ),
        (
            defining_scope.clone(),
            ArtifactDbView::open(&defining_artifact, registry.schemas()).unwrap(),
        ),
    ])
    .unwrap();
    let index = WorkspaceProgramIndex::open(
        &workspace,
        [
            VerifiedArtifactOwner::new(consumer_scope.clone(), 54),
            VerifiedArtifactOwner::new(defining_scope.clone(), 55),
        ],
    )
    .unwrap();
    let authority = VerifiedDefiningScopeMap::new(
        &workspace,
        &index,
        [DefiningScopeAuthority::new(
            consumer_scope.clone(),
            55,
            StableCrateResolution::Managed(defining_scope),
        )],
    )
    .unwrap();
    let mut policy = ReconciliationMarkerPolicy::new(decision);
    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request(
            "sniff-test.test.reconciliation-markers",
            consumer_scope,
            consumer,
        ),
        &mut policy,
    )
    .unwrap();
    (policy, resolve_prepared(prepared, &workspace, registry))
}

#[test]
fn defining_markers_are_decided_once_and_transport_all_or_none_to_raw_and_synthetic_calls() {
    let registry = registry();
    for (generation, decision, expected_active) in [
        (0, DefiningMarkerDecision::RejectCompleteSet, 0),
        (1, DefiningMarkerDecision::UseCompleteSet, 2),
    ] {
        let (policy, traversal) = run_reconciliation_marker_case(&registry, generation, decision);
        assert_eq!(policy.defining_calls, 1);
        assert_eq!(policy.candidate_marker_counts, vec![vec![1, 1]]);
        assert_eq!(policy.call_active_marker_counts, vec![expected_active; 2]);
        assert!(matches!(
            policy.resolutions[0],
            ProgramCallResolution::Persisted
        ));
        assert!(matches!(
            policy.resolutions[1],
            ProgramCallResolution::CallableEvidence { .. }
        ));
        let invocation = traversal
            .occurrence_visits()
            .iter()
            .find(|visit| visit.kind() == CallKind::IndirectCall)
            .unwrap();
        assert_eq!(invocation.attached_marker_candidates().len(), 0);
        assert_eq!(invocation.active_markers().len(), expected_active);
        for marker in invocation.active_markers() {
            assert_eq!(
                marker
                    .trace()
                    .relations()
                    .iter()
                    .rev()
                    .take(2)
                    .map(|relation| relation.schema().as_str())
                    .collect::<Vec<_>>(),
                vec![
                    CallOccurrenceHasMarkerClaimCandidate::ID,
                    ConsumerOccurrenceReconcilesWith::ID,
                ]
            );
        }
        assert!(
            traversal
                .consumer_reconciliations()
                .iter()
                .all(|reconciliation| invocation.order() < reconciliation.order())
        );
    }
}

struct AuthoritySelectionRun {
    policy: ReconciliationAuthorityPolicy,
    traversal: ResolvedRootProgramTraversal<&'static str>,
    defining_scope: ArtifactScopeId,
    target: FunctionKey,
}

fn run_defining_target_authority_selection(
    registry: &AnalysisRegistry<CollectedArtifact>,
) -> AuthoritySelectionRun {
    let consumer_scope = ArtifactScopeId::for_in_memory(60, 0);
    let defining_scope = ArtifactScopeId::for_in_memory(61, 0);
    let consumer = FunctionKey::new(definition(61, 1), Some(instance(1)));
    let defining = FunctionKey::new(consumer.definition(), None);
    let target = FunctionKey::new(definition(61, 2), Some(instance(1)));
    let mut consumer_builder = ConfiguredCallArtifactBuilder::new_with_provenance(
        registry,
        consumer,
        FunctionBodyProvenance::ConsumerInstantiation {
            consumer_stable_crate_id: 60,
        },
    );
    let consumer_target = consumer_builder
        .insert_target(target, TargetFixture::SeparateWithoutBody)
        .unwrap();
    let consumer_call = consumer_builder.insert_call_for(consumer, 0, Some(&consumer_target));
    consumer_builder.attach_call_source_anchor(&consumer_call, CallSourceAnchorRole::Expanded);
    let consumer_artifact = consumer_builder.finish(registry);
    let mut defining_builder = ConfiguredCallArtifactBuilder::new(registry, defining);
    let defining_target = defining_builder
        .insert_target(target, TargetFixture::SeparateWithBody)
        .unwrap();
    let defining_call = defining_builder.insert_call_for(defining, 0, Some(&defining_target));
    defining_builder.attach_call_source_anchor(&defining_call, CallSourceAnchorRole::Expanded);
    let defining_artifact = defining_builder.finish(registry);
    let workspace = WorkspaceFactView::compose([
        (
            consumer_scope.clone(),
            ArtifactDbView::open(&consumer_artifact, registry.schemas()).unwrap(),
        ),
        (
            defining_scope.clone(),
            ArtifactDbView::open(&defining_artifact, registry.schemas()).unwrap(),
        ),
    ])
    .unwrap();
    let index = WorkspaceProgramIndex::open(
        &workspace,
        [
            VerifiedArtifactOwner::new(consumer_scope.clone(), 60),
            VerifiedArtifactOwner::new(defining_scope.clone(), 61),
        ],
    )
    .unwrap();
    let authority = VerifiedDefiningScopeMap::new(
        &workspace,
        &index,
        [DefiningScopeAuthority::new(
            consumer_scope.clone(),
            61,
            StableCrateResolution::Managed(defining_scope.clone()),
        )],
    )
    .unwrap();
    let mut policy = ReconciliationAuthorityPolicy {
        follow_defining_target: true,
        observed: Vec::new(),
    };
    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request(
            "sniff-test.test.defining-target-authority",
            consumer_scope,
            consumer,
        ),
        &mut policy,
    )
    .unwrap();
    AuthoritySelectionRun {
        policy,
        traversal: resolve_prepared(prepared, &workspace, registry),
        defining_scope,
        target,
    }
}

#[test]
fn defining_target_authority_precedence_is_followable_on_the_exact_reconciliation_route() {
    let registry = registry();
    let run = run_defining_target_authority_selection(&registry);
    assert_eq!(
        run.policy.observed,
        vec![ObservedReconciliationAuthorities {
            resolution: ProgramCallResolution::Persisted,
            raw: Some(ReconciledCallTargetAuthority::ConsumerRaw),
            raw_role: Some(CallTargetRole::Runtime),
            defining_source: None,
            effective_source: None,
            defining_target: Some(ReconciledCallTargetAuthority::DefiningTarget),
            metadata: vec![
                ReconciledCallTargetAuthority::ConsumerRaw,
                ReconciledCallTargetAuthority::DefiningTarget,
            ],
            contract: vec![ReconciledCallTargetAuthority::ConsumerRaw],
            candidates: 1,
        }]
    );
    let selected = run
        .traversal
        .body_visits()
        .iter()
        .find(|visit| visit.function() == run.target)
        .expect("the defining target body is followed");
    let [followed] = run.traversal.followed_calls() else {
        panic!("the defining-target selection is retained as one followed call");
    };
    assert_eq!(
        followed.target().authority(),
        ReconciledCallTargetAuthority::DefiningTarget
    );
    assert_eq!(followed.target().role(), CallTargetRole::Runtime);
    assert_eq!(followed.target().callable().scope(), &run.defining_scope);
    assert_eq!(*followed.target_data().key(), run.target);
    assert!(matches!(
        followed.source_anchors(),
        [anchor]
            if anchor.role() == CallSourceAnchorRole::Expanded
                && anchor.relation().scope() == followed.occurrence().scope()
                && anchor.relation().relation().schema.as_str()
                    == CallOccurrenceHasSourceAnchor::ID
    ));
    assert_eq!(
        followed.trace().target(),
        &followed.target().callable().erase()
    );
    assert_eq!(selected.body().scope(), &run.defining_scope);
    assert_eq!(
        selected
            .trace()
            .relations()
            .iter()
            .map(|relation| relation.schema().as_str())
            .collect::<Vec<_>>(),
        vec![
            FunctionOwnsCallSite::ID,
            CallSiteHasOccurrence::ID,
            ConsumerOccurrenceReconcilesWith::ID,
            CallOccurrenceTargetsCallable::ID,
            CallableSelectsFunctionBody::ID,
        ]
    );
    assert_eq!(
        followed
            .trace()
            .relations()
            .iter()
            .map(|relation| relation.schema().as_str())
            .collect::<Vec<_>>(),
        vec![
            FunctionOwnsCallSite::ID,
            CallSiteHasOccurrence::ID,
            ConsumerOccurrenceReconcilesWith::ID,
            CallOccurrenceTargetsCallable::ID,
        ]
    );
}

#[test]
fn defining_target_consensus_requires_the_same_role_and_scoped_callable() {
    let registry = registry();
    let consumer_scope = ArtifactScopeId::for_in_memory(60, 1);
    let defining_scope = ArtifactScopeId::for_in_memory(61, 1);
    let consumer = FunctionKey::new(definition(61, 2), Some(instance(2)));
    let defining = FunctionKey::new(consumer.definition(), None);
    let opaque = FunctionKey::new(definition(63, 1), None);
    let mut consumer_builder = ConfiguredCallArtifactBuilder::new_with_provenance(
        &registry,
        consumer,
        FunctionBodyProvenance::ConsumerInstantiation {
            consumer_stable_crate_id: 60,
        },
    );
    let consumer_call = consumer_builder.insert_call_for(consumer, 0, None);
    consumer_builder.attach_call_source_anchor(&consumer_call, CallSourceAnchorRole::Expanded);
    let consumer_artifact = consumer_builder.finish(&registry);
    let mut defining_builder = ConfiguredCallArtifactBuilder::new(&registry, defining);
    let opaque_target = defining_builder
        .insert_target(opaque, TargetFixture::SeparateWithoutBody)
        .unwrap();
    let callable_key = defining_builder
        .builder
        .insert_entity(&CallableKeyEntity::new(CallableKey::DynDispatch(
            definition(63, 9),
        )))
        .unwrap();
    for (local_id, role) in [CallTargetRole::OpaqueTrait, CallTargetRole::OpaqueFunction]
        .into_iter()
        .enumerate()
    {
        let occurrence = defining_builder.insert_keyed_call_for(
            defining,
            u32::try_from(local_id).unwrap(),
            CallKind::DirectCall,
            vec![CallAttributionRole::CallSite],
            &callable_key,
            &[(role, opaque_target.clone())],
        );
        defining_builder.attach_call_source_anchor(&occurrence, CallSourceAnchorRole::Expanded);
    }
    let defining_artifact = defining_builder.finish(&registry);
    let workspace = WorkspaceFactView::compose([
        (
            consumer_scope.clone(),
            ArtifactDbView::open(&consumer_artifact, registry.schemas()).unwrap(),
        ),
        (
            defining_scope.clone(),
            ArtifactDbView::open(&defining_artifact, registry.schemas()).unwrap(),
        ),
    ])
    .unwrap();
    let index = WorkspaceProgramIndex::open(
        &workspace,
        [
            VerifiedArtifactOwner::new(consumer_scope.clone(), 60),
            VerifiedArtifactOwner::new(defining_scope.clone(), 61),
        ],
    )
    .unwrap();
    let authority = VerifiedDefiningScopeMap::new(
        &workspace,
        &index,
        [DefiningScopeAuthority::new(
            consumer_scope.clone(),
            61,
            StableCrateResolution::Managed(defining_scope),
        )],
    )
    .unwrap();
    let mut policy = ReconciliationAuthorityPolicy::default();
    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request(
            "sniff-test.test.role-sensitive-consensus",
            consumer_scope,
            consumer,
        ),
        &mut policy,
    )
    .unwrap();

    assert_eq!(prepared.consumer_reconciliations.len(), 2);
    assert!(
        prepared
            .consumer_reconciliations
            .iter()
            .all(|reconciliation| {
                reconciliation.kind == ConsumerOccurrenceReconciliationKind::SourceFallback
            })
    );
    assert_eq!(policy.observed.len(), 1);
    assert_eq!(policy.observed[0].candidates, 2);
    assert_eq!(policy.observed[0].defining_target, None);
}

fn opaque_raw_and_synthetic_authority_artifacts(
    registry: &AnalysisRegistry<CollectedArtifact>,
) -> (ArtifactFactIr, ArtifactFactIr, FunctionKey) {
    let consumer = FunctionKey::new(definition(65, 1), Some(instance(1)));
    let defining = FunctionKey::new(consumer.definition(), None);
    let key = CallableKey::FnPointer(type_hash(64));
    let mut consumer_builder = ConfiguredCallArtifactBuilder::new_with_provenance(
        registry,
        consumer,
        FunctionBodyProvenance::ConsumerInstantiation {
            consumer_stable_crate_id: 64,
        },
    );
    let opaque_target = consumer_builder
        .insert_target(
            FunctionKey::new(definition(66, 1), None),
            TargetFixture::SeparateWithoutBody,
        )
        .unwrap();
    let evidence_target = consumer_builder
        .insert_target(
            FunctionKey::new(definition(64, 2), Some(instance(2))),
            TargetFixture::SeparateWithoutBody,
        )
        .unwrap();
    let callable_key = consumer_builder
        .builder
        .insert_entity(&CallableKeyEntity::new(key))
        .unwrap();
    let invocation = consumer_builder.insert_keyed_call_for(
        consumer,
        0,
        CallKind::IndirectCall,
        vec![CallAttributionRole::CallSite],
        &callable_key,
        &[(CallTargetRole::OpaqueTrait, opaque_target)],
    );
    consumer_builder.attach_call_source_anchor(&invocation, CallSourceAnchorRole::Expanded);
    consumer_builder.insert_keyed_call_for(
        consumer,
        1,
        CallKind::FnPointerReify,
        vec![CallAttributionRole::ErasureSite],
        &callable_key,
        &[(CallTargetRole::Runtime, evidence_target)],
    );
    let consumer_artifact = consumer_builder.finish(registry);
    let mut defining_builder = ConfiguredCallArtifactBuilder::new(registry, defining);
    let defining_target = defining_builder
        .insert_target(
            FunctionKey::new(definition(67, 1), Some(instance(1))),
            TargetFixture::SeparateWithoutBody,
        )
        .unwrap();
    let defining_callable_key = defining_builder
        .builder
        .insert_entity(&CallableKeyEntity::new(CallableKey::FnPointer(type_hash(
            65,
        ))))
        .unwrap();
    let defining_call = defining_builder.insert_keyed_call_for(
        defining,
        0,
        CallKind::IndirectCall,
        vec![CallAttributionRole::CallSite],
        &defining_callable_key,
        &[(CallTargetRole::Runtime, defining_target)],
    );
    defining_builder.attach_call_source_anchor(&defining_call, CallSourceAnchorRole::Expanded);
    (
        consumer_artifact,
        defining_builder.finish(registry),
        consumer,
    )
}

fn observe_opaque_raw_and_synthetic_reconciliation_authorities(
    registry: &AnalysisRegistry<CollectedArtifact>,
) -> ReconciliationAuthorityPolicy {
    let consumer_scope = ArtifactScopeId::for_in_memory(64, 0);
    let defining_scope = ArtifactScopeId::for_in_memory(65, 0);
    let (consumer_artifact, defining_artifact, consumer) =
        opaque_raw_and_synthetic_authority_artifacts(registry);
    let workspace = WorkspaceFactView::compose([
        (
            consumer_scope.clone(),
            ArtifactDbView::open(&consumer_artifact, registry.schemas()).unwrap(),
        ),
        (
            defining_scope.clone(),
            ArtifactDbView::open(&defining_artifact, registry.schemas()).unwrap(),
        ),
    ])
    .unwrap();
    let index = WorkspaceProgramIndex::open(
        &workspace,
        [
            VerifiedArtifactOwner::new(consumer_scope.clone(), 64),
            VerifiedArtifactOwner::new(defining_scope.clone(), 65),
        ],
    )
    .unwrap();
    let authority = VerifiedDefiningScopeMap::new(
        &workspace,
        &index,
        [DefiningScopeAuthority::new(
            consumer_scope.clone(),
            65,
            StableCrateResolution::Managed(defining_scope),
        )],
    )
    .unwrap();
    let mut policy = ReconciliationAuthorityPolicy::default();
    PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request(
            "sniff-test.test.opaque-reconciliation-authority",
            consumer_scope,
            consumer,
        ),
        &mut policy,
    )
    .unwrap();
    policy
}

#[test]
fn opaque_raw_authority_precedes_defining_for_raw_and_synthetic_policy_snapshots() {
    let registry = registry();
    let policy = observe_opaque_raw_and_synthetic_reconciliation_authorities(&registry);
    assert_eq!(policy.observed.len(), 2);
    assert!(matches!(
        policy.observed[0].resolution,
        ProgramCallResolution::Persisted
    ));
    assert!(matches!(
        policy.observed[1].resolution,
        ProgramCallResolution::CallableEvidence { .. }
    ));
    assert_eq!(
        policy.observed[0].raw_role,
        Some(CallTargetRole::OpaqueTrait)
    );
    assert_eq!(policy.observed[1].raw_role, Some(CallTargetRole::Runtime));
    for observed in &policy.observed {
        assert_eq!(
            observed.metadata,
            vec![
                ReconciledCallTargetAuthority::ConsumerRaw,
                ReconciledCallTargetAuthority::DefiningTarget,
            ]
        );
        assert_eq!(
            observed.contract,
            vec![ReconciledCallTargetAuthority::ConsumerRaw],
            "an effective raw target prevents defining-target contract fallback"
        );
    }
}

#[test]
fn emit_rolls_back_an_earlier_program_schema_when_a_later_schema_is_missing() {
    let registry = registry();
    let consumer_scope = ArtifactScopeId::for_in_memory(34, 0);
    let defining_scope = ArtifactScopeId::for_in_memory(35, 0);
    let root = FunctionKey::new(definition(34, 1), Some(instance(1)));
    let consumer = FunctionKey::new(definition(35, 2), Some(instance(2)));
    let generic = FunctionKey::new(consumer.definition(), None);
    let mut caller = ConfiguredCallArtifactBuilder::new(&registry, root);
    let target = caller.insert_consumer_target(consumer, 34);
    caller.insert_calls(
        &ConfiguredCall {
            kind: CallKind::DirectCall,
            attribution: vec![CallAttributionRole::CallSite],
            callable_key: None,
            target: TargetFixture::None,
            call_count: 1,
            route: CallRoute::Site,
            marker: None,
        },
        Some(&target),
    );
    let caller_artifact = caller.finish(&registry);
    let defining_artifact = root_artifact(
        &registry,
        &[(generic, FunctionBodyProvenance::DefiningArtifact)],
    );
    let workspace = WorkspaceFactView::compose([
        (
            consumer_scope.clone(),
            ArtifactDbView::open(&caller_artifact, registry.schemas()).unwrap(),
        ),
        (
            defining_scope.clone(),
            ArtifactDbView::open(&defining_artifact, registry.schemas()).unwrap(),
        ),
    ])
    .unwrap();
    let index = WorkspaceProgramIndex::open(
        &workspace,
        [
            VerifiedArtifactOwner::new(consumer_scope.clone(), 34),
            VerifiedArtifactOwner::new(defining_scope.clone(), 35),
        ],
    )
    .unwrap();
    let authority = VerifiedDefiningScopeMap::new(
        &workspace,
        &index,
        [DefiningScopeAuthority::new(
            consumer_scope.clone(),
            35,
            StableCrateResolution::Managed(defining_scope),
        )],
    )
    .unwrap();
    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &request("sniff-test.test.emit-atomic", consumer_scope, root),
        &mut FollowRuntimePolicy,
    )
    .unwrap();
    assert_eq!(prepared.composition_edge_count(), 2);

    let mut incomplete_registry = CompositionRelationRegistry::new();
    incomplete_registry
        .register::<CallableSelectsFunctionBody>(registry.schemas())
        .unwrap();
    let mut builder =
        CompositionRelationBuilder::new(prepared.root(), &workspace, &incomplete_registry).unwrap();
    assert!(matches!(
        prepared.emit(&mut builder),
        Err(RootProgramTraversalError::Composition(
            CompositionBuildError::Registry { .. }
        ))
    ));
    assert_eq!(builder.finalize().unwrap().relations().len(), 0);
}

#[test]
fn emit_rejects_replacement_workspace_and_wrong_root_before_adding_relations() {
    let registry = registry();
    let scope = ArtifactScopeId::for_in_memory(32, 0);
    let root = FunctionKey::new(definition(32, 1), Some(instance(1)));
    let artifact = root_artifact(
        &registry,
        &[(root, FunctionBodyProvenance::DefiningArtifact)],
    );
    let original_view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
    let original = WorkspaceFactView::compose([(scope.clone(), original_view)]).unwrap();
    let index =
        WorkspaceProgramIndex::open(&original, [VerifiedArtifactOwner::new(scope.clone(), 32)])
            .unwrap();
    let authority = VerifiedDefiningScopeMap::new(&original, &index, []).unwrap();

    let prepared = PreparedRootProgramTraversal::prepare(
        &original,
        &index,
        &authority,
        &request("sniff-test.test.emit-brand", scope.clone(), root),
        &mut ExpandPolicy,
    )
    .unwrap();
    let replacement_view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
    let replacement = WorkspaceFactView::compose([(scope.clone(), replacement_view)]).unwrap();
    let mut replacement_builder = CompositionRelationBuilder::new(
        prepared.root(),
        &replacement,
        registry.composition_relations(),
    )
    .unwrap();
    assert!(matches!(
        prepared.emit(&mut replacement_builder),
        Err(RootProgramTraversalError::WorkspaceMismatch)
    ));
    assert_eq!(replacement_builder.finalize().unwrap().relations().len(), 0);

    let prepared = PreparedRootProgramTraversal::prepare(
        &original,
        &index,
        &authority,
        &request("sniff-test.test.emit-brand", scope, root),
        &mut ExpandPolicy,
    )
    .unwrap();
    let wrong_root = EvaluationRoot::new(
        DomainId::new("sniff-test.test.wrong-root").unwrap(),
        prepared.root().entity.clone(),
    );
    let mut wrong_root_builder =
        CompositionRelationBuilder::new(&wrong_root, &original, registry.composition_relations())
            .unwrap();
    assert!(matches!(
        prepared.emit(&mut wrong_root_builder),
        Err(RootProgramTraversalError::RootMismatch { .. })
    ));
    assert_eq!(wrong_root_builder.finalize().unwrap().relations().len(), 0);
}

#[test]
fn resolve_rejects_missing_and_unexpected_program_composition_edges() {
    let registry = registry();
    let scope = ArtifactScopeId::for_in_memory(33, 0);
    let root = FunctionKey::new(definition(33, 1), Some(instance(1)));
    let target = FunctionKey::new(definition(33, 2), Some(instance(2)));
    let artifact = direct_call_artifact(&registry, root, target);
    let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
    let workspace = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
    let index =
        WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 33)])
            .unwrap();
    let authority = VerifiedDefiningScopeMap::new(&workspace, &index, []).unwrap();
    let traversal_request = request("sniff-test.test.resolve-hostility", scope.clone(), root);

    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &traversal_request,
        &mut FollowRuntimePolicy,
    )
    .unwrap();
    let mut expected_builder = CompositionRelationBuilder::new(
        prepared.root(),
        &workspace,
        registry.composition_relations(),
    )
    .unwrap();
    let emitted = prepared.emit(&mut expected_builder).unwrap();
    let empty = CompositionRelationBuilder::new(
        emitted.root(),
        &workspace,
        registry.composition_relations(),
    )
    .unwrap()
    .finalize()
    .unwrap();
    let missing_graph = WorkspaceRelationGraph::new(emitted.root(), &workspace, &empty).unwrap();
    assert!(matches!(
        emitted.resolve(&missing_graph, registry.composition_relations()),
        Err(RootProgramTraversalError::MissingCompositionEdge { .. })
    ));

    let prepared = PreparedRootProgramTraversal::prepare(
        &workspace,
        &index,
        &authority,
        &traversal_request,
        &mut ExpandPolicy,
    )
    .unwrap();
    assert_eq!(prepared.composition_edge_count(), 0);
    let mut expected_builder = CompositionRelationBuilder::new(
        prepared.root(),
        &workspace,
        registry.composition_relations(),
    )
    .unwrap();
    let emitted = prepared.emit(&mut expected_builder).unwrap();
    let callable = index
        .exact_callable(&scope, &target)
        .expect("target callable exists")
        .id();
    let body = index
        .exact_function(&scope, &target)
        .expect("target body exists")
        .id();
    let mut unexpected_builder = CompositionRelationBuilder::new(
        emitted.root(),
        &workspace,
        registry.composition_relations(),
    )
    .unwrap();
    unexpected_builder
        .relate(
            &callable,
            &body,
            &CallableSelectsFunctionBody::new(CallableBodySelectionKind::ExactPreferred),
        )
        .unwrap();
    let unexpected = unexpected_builder.finalize().unwrap();
    let unexpected_graph =
        WorkspaceRelationGraph::new(emitted.root(), &workspace, &unexpected).unwrap();
    assert!(matches!(
        emitted.resolve(&unexpected_graph, registry.composition_relations()),
        Err(RootProgramTraversalError::UnexpectedCompositionEdge { .. })
    ));
}
