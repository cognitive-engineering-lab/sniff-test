use reachability::MirBodyLocation;
use serde_json::json;

use super::*;
use crate::analysis::collected::CollectedArtifact;
use crate::analysis::facts::builder::ArtifactDbBuilder;
use crate::analysis::facts::encoded::ArtifactFactIr;
use crate::analysis::facts::evaluation::DomainId;
use crate::analysis::facts::human::EvidenceClaimSelector;
use crate::analysis::facts::human::markers::{
    CallOccurrenceHasMarkerClaimCandidate, HumanMarkerCollectionPack, MarkerClaimEntity,
    MarkerClaimKey, MarkerOccurrenceEntity, MarkerOccurrenceHasClaim,
    MarkerOccurrenceHasSourceAnchor, MarkerOccurrenceKey,
};
use crate::analysis::facts::pack::AnalysisRegistry;
use crate::analysis::facts::panic::contract_collector::PanicContractCollectionPack;
use crate::analysis::facts::program::collector::CoreProgramCollectionPack;
use crate::analysis::facts::program::topology::{
    CallAttributionRole, CallKind, CallMacroExpansionEntersCallMacroExpansion,
    CallMacroExpansionEntity, CallMacroExpansionHasCallsite, CallMacroExpansionKey,
    CallMacroExpansionProducesCallOccurrence, CallOccurrenceEntity, CallOccurrenceHasCallableKey,
    CallOccurrenceHasSourceAnchor, CallOccurrenceInSafetyEffectGroup, CallOccurrenceKey,
    CallOccurrenceTargetsCallable, CallSiteEntity, CallSiteHasOccurrence, CallSiteKey,
    CallSourceAnchorRole, CallTargetRole, CallableEntity, CallableKey, CallableKeyEntity,
    FunctionDefinesCallable, FunctionEntersCallMacroExpansion, FunctionOwnsCallSite,
    FunctionOwnsSafetyEffectGroup, SafetyEffectGroupEntity, SafetyEffectGroupKey,
};
use crate::analysis::facts::program::{
    CoreProgramPack, EffectSiteEntity, EffectSiteHasSourceAnchor, EffectSiteKey,
    EffectSourceAnchorRole, FunctionBodyProvenance, FunctionEntersMacroExpansion, FunctionEntity,
    FunctionHasSourceAnchor, FunctionKey, FunctionOwnsEffectSite,
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
use crate::analysis::facts::schema::{EntityHandle, RelationSchema, RowSchema};
use crate::analysis::facts::view::ArtifactDbView;
use crate::analysis::facts::workspace::{
    ArtifactScopeId, ScopedEntityRef, ScopedRelationRef, WorkspaceFactView,
};
use crate::namespace::{
    StableDefPathHash, StableExpansionHash, StableInstanceHash, StableTypeHash,
};

fn definition(value: u128) -> StableDefPathHash {
    serde_json::from_str(&format!("\"{value:032x}\"")).expect("valid definition hash")
}

fn definition_in_crate(stable_crate_id: u64, local: u64) -> StableDefPathHash {
    serde_json::from_str(&format!("\"{stable_crate_id:016x}{local:016x}\""))
        .expect("valid definition hash")
}

fn type_hash(value: u128) -> StableTypeHash {
    serde_json::from_str(&format!("\"{value:032x}\"")).expect("valid type hash")
}

fn instance(value: u128) -> StableInstanceHash {
    serde_json::from_str(&format!("\"{value:032x}\"")).expect("valid instance hash")
}

fn expansion(value: u128) -> StableExpansionHash {
    serde_json::from_str(&format!("\"{value:032x}\"")).expect("valid expansion hash")
}

fn function(value: u128, instance_value: Option<u128>) -> FunctionKey {
    FunctionKey::new(definition(value), instance_value.map(instance))
}

fn scope(value: &str) -> ArtifactScopeId {
    ArtifactScopeId::new(value).expect("valid test scope")
}

fn verified(scope: &ArtifactScopeId, stable_crate_id: u64) -> VerifiedArtifactOwner {
    VerifiedArtifactOwner::new(scope.clone(), stable_crate_id)
}

fn assert_scoped_relation<R: RowSchema>(
    reference: &ScopedRelationRef,
    expected_scope: &ArtifactScopeId,
) {
    assert_eq!(reference.scope(), expected_scope);
    assert_eq!(reference.relation().schema.as_str(), R::ID);
}

fn assert_relation_endpoints(
    workspace: &WorkspaceFactView<'_>,
    reference: &ScopedRelationRef,
    expected_from: &ScopedEntityRef,
    expected_to: &ScopedEntityRef,
) {
    let relation = workspace.relation(reference).unwrap();
    assert_eq!(relation.from(), expected_from);
    assert_eq!(relation.to(), expected_to);
}

fn artifact_registry() -> AnalysisRegistry<CollectedArtifact> {
    let mut registry = AnalysisRegistry::<CollectedArtifact>::new();
    registry.install(&CoreProgramCollectionPack).unwrap();
    registry.install(&PanicContractCollectionPack).unwrap();
    registry.install(&SafetyCollectionPack).unwrap();
    registry.install(&HumanMarkerCollectionPack).unwrap();
    registry
}

fn program_artifact(
    registry: &AnalysisRegistry<CollectedArtifact>,
    functions: &[(FunctionKey, FunctionBodyProvenance)],
) -> ArtifactFactIr {
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
    let anchor = builder
        .insert_entity(&SourceAnchorEntity::new(SourceAnchorKey::new(
            "src/lib.rs",
            0,
            10,
        )))
        .unwrap();
    builder
        .relate(&anchor, &file, &SourceAnchorInFile::new())
        .unwrap();

    for (key, provenance) in functions {
        let function = builder
            .insert_entity(&FunctionEntity::new(
                *key,
                format!("crate::body::{key:?}"),
                *provenance,
            ))
            .unwrap();
        let callable = builder
            .insert_entity(&CallableEntity::new(
                *key,
                format!("crate::callable::{key:?}"),
                false,
                false,
                true,
                false,
                vec![String::from("crate::body")],
            ))
            .unwrap();
        builder
            .relate(&function, &callable, &FunctionDefinesCallable::new())
            .unwrap();
    }
    builder.finalize(registry.schemas()).unwrap()
}

fn malformed_marker_artifact(registry: &AnalysisRegistry<CollectedArtifact>) -> ArtifactFactIr {
    let mut builder = ArtifactDbBuilder::new();
    for descriptor in registry.schemas().descriptors() {
        builder.declare_table(descriptor).unwrap();
    }

    let anchor_key = SourceAnchorKey::new("src/lib.rs", 0, 10);
    let file = builder
        .insert_entity(&SourceFileEntity::new(
            "src/lib.rs",
            "src/lib.rs",
            "verified-hash",
            100,
        ))
        .unwrap();
    let anchor = builder
        .insert_entity(&SourceAnchorEntity::new(anchor_key.clone()))
        .unwrap();
    builder
        .relate(&anchor, &file, &SourceAnchorInFile::new())
        .unwrap();

    let owner = function(45, None);
    let body = builder
        .insert_entity(&FunctionEntity::new(
            owner,
            "crate::owner",
            FunctionBodyProvenance::DefiningArtifact,
        ))
        .unwrap();
    let callable = builder
        .insert_entity(&CallableEntity::new(
            owner,
            "crate::owner",
            false,
            false,
            true,
            false,
            vec![String::from("crate::owner")],
        ))
        .unwrap();
    builder
        .relate(&body, &callable, &FunctionDefinesCallable::new())
        .unwrap();

    let marker = builder
        .insert_entity(&MarkerOccurrenceEntity::new(
            MarkerOccurrenceKey::new(anchor_key, None),
            vec![expansion(45)],
        ))
        .unwrap();
    builder
        .relate(&marker, &anchor, &MarkerOccurrenceHasSourceAnchor::new())
        .unwrap();
    builder.finalize(registry.schemas()).unwrap()
}

fn malformed_unsafe_artifact(registry: &AnalysisRegistry<CollectedArtifact>) -> ArtifactFactIr {
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
    let anchor = builder
        .insert_entity(&SourceAnchorEntity::new(SourceAnchorKey::new(
            "src/lib.rs",
            0,
            10,
        )))
        .unwrap();
    builder
        .relate(&anchor, &file, &SourceAnchorInFile::new())
        .unwrap();

    let owner = function(46, None);
    let body = builder
        .insert_entity(&FunctionEntity::new(
            owner,
            "crate::owner",
            FunctionBodyProvenance::DefiningArtifact,
        ))
        .unwrap();
    let callable = builder
        .insert_entity(&CallableEntity::new(
            owner,
            "crate::owner",
            false,
            false,
            true,
            false,
            vec![String::from("crate::owner")],
        ))
        .unwrap();
    builder
        .relate(&body, &callable, &FunctionDefinesCallable::new())
        .unwrap();
    let group = builder
        .insert_entity(&SafetyEffectGroupEntity::new(SafetyEffectGroupKey::new(
            owner, 0,
        )))
        .unwrap();
    builder
        .relate(&body, &group, &FunctionOwnsSafetyEffectGroup::new())
        .unwrap();
    builder
        .insert_entity(&UnsafeOperationEntity::new(
            UnsafeOperationKey::new(owner, 0),
            SafetyOperationKind::DerefRawPointer,
        ))
        .unwrap();
    builder.finalize(registry.schemas()).unwrap()
}

fn function_anchor_artifact(
    registry: &AnalysisRegistry<CollectedArtifact>,
    anchor_relations: &[usize],
) -> (ArtifactFactIr, FunctionKey, SourceAnchorKey) {
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
    let anchor_keys = [
        SourceAnchorKey::new("src/lib.rs", 0, 10),
        SourceAnchorKey::new("src/lib.rs", 20, 30),
    ];
    let anchors = anchor_keys
        .iter()
        .map(|key| {
            let anchor = builder
                .insert_entity(&SourceAnchorEntity::new(key.clone()))
                .unwrap();
            builder
                .relate(&anchor, &file, &SourceAnchorInFile::new())
                .unwrap();
            anchor
        })
        .collect::<Vec<_>>();
    let function_key = function(47, None);
    let body = builder
        .insert_entity(&FunctionEntity::new(
            function_key,
            "crate::owner",
            FunctionBodyProvenance::DefiningArtifact,
        ))
        .unwrap();
    let callable = builder
        .insert_entity(&CallableEntity::new(
            function_key,
            "crate::owner",
            false,
            false,
            true,
            false,
            vec![String::from("crate::owner")],
        ))
        .unwrap();
    builder
        .relate(&body, &callable, &FunctionDefinesCallable::new())
        .unwrap();
    for &anchor in anchor_relations {
        builder
            .relate(&body, &anchors[anchor], &FunctionHasSourceAnchor::new())
            .unwrap();
    }
    (
        builder.finalize(registry.schemas()).unwrap(),
        function_key,
        anchor_keys[0].clone(),
    )
}

#[derive(Clone, Copy)]
enum EffectArtifactShape {
    Direct,
    Macro,
}

#[derive(Clone, Copy, Debug)]
enum EffectArtifactFault {
    MissingOwner,
    DuplicateOwner,
    DuplicateSourceRole,
    NoncontiguousMacroDepth,
    MissingMacroEntry,
    SurplusMacroEntry,
    ReversedMacroLink,
    MissingMacroExit,
    DuplicateMacroExit,
    DuplicateMacroCallsite,
}

fn insert_effect_source_anchors(
    builder: &mut ArtifactDbBuilder,
) -> (
    EntityHandle<SourceAnchorEntity>,
    EntityHandle<SourceAnchorEntity>,
) {
    let file = builder
        .insert_entity(&SourceFileEntity::new(
            "src/lib.rs",
            "src/lib.rs",
            "verified-hash",
            100,
        ))
        .unwrap();
    let presentation = builder
        .insert_entity(&SourceAnchorEntity::new(SourceAnchorKey::new(
            "src/lib.rs",
            10,
            20,
        )))
        .unwrap();
    let expanded = builder
        .insert_entity(&SourceAnchorEntity::new(SourceAnchorKey::new(
            "src/lib.rs",
            30,
            40,
        )))
        .unwrap();
    builder
        .relate(&presentation, &file, &SourceAnchorInFile::new())
        .unwrap();
    builder
        .relate(&expanded, &file, &SourceAnchorInFile::new())
        .unwrap();
    (presentation, expanded)
}

fn insert_effect_macro_path(
    builder: &mut ArtifactDbBuilder,
    owner_number: u128,
    fault: Option<EffectArtifactFault>,
    body: &EntityHandle<FunctionEntity>,
    effect: &EntityHandle<EffectSiteEntity>,
    presentation: &EntityHandle<SourceAnchorEntity>,
    expanded: &EntityHandle<SourceAnchorEntity>,
) {
    // Reverse insertion order proves semantic depth, not row order, owns the path.
    let inner_depth = if matches!(fault, Some(EffectArtifactFault::NoncontiguousMacroDepth)) {
        2
    } else {
        1
    };
    let inner = builder
        .insert_entity(&MacroExpansionEntity::new(
            MacroExpansionKey::new(*effect.key(), inner_depth),
            expansion(owner_number + 1),
            definition(owner_number + 101),
            "crate::inner_macro",
        ))
        .unwrap();
    let outer = builder
        .insert_entity(&MacroExpansionEntity::new(
            MacroExpansionKey::new(*effect.key(), 0),
            expansion(owner_number),
            definition(owner_number + 100),
            "crate::outer_macro",
        ))
        .unwrap();
    if !matches!(fault, Some(EffectArtifactFault::MissingMacroEntry)) {
        builder
            .relate(body, &outer, &FunctionEntersMacroExpansion::new())
            .unwrap();
    }
    if matches!(fault, Some(EffectArtifactFault::SurplusMacroEntry)) {
        builder
            .relate(body, &inner, &FunctionEntersMacroExpansion::new())
            .unwrap();
    }
    if matches!(fault, Some(EffectArtifactFault::ReversedMacroLink)) {
        builder
            .relate(&inner, &outer, &MacroExpansionEntersMacroExpansion::new())
            .unwrap();
    } else {
        builder
            .relate(&outer, &inner, &MacroExpansionEntersMacroExpansion::new())
            .unwrap();
    }
    if !matches!(fault, Some(EffectArtifactFault::MissingMacroExit)) {
        builder
            .relate(&inner, effect, &MacroExpansionProducesEffectSite::new())
            .unwrap();
    }
    if matches!(fault, Some(EffectArtifactFault::DuplicateMacroExit)) {
        builder
            .relate(&inner, effect, &MacroExpansionProducesEffectSite::new())
            .unwrap();
    }
    builder
        .relate(&outer, presentation, &MacroExpansionHasCallsite::new())
        .unwrap();
    if matches!(fault, Some(EffectArtifactFault::DuplicateMacroCallsite)) {
        builder
            .relate(&outer, expanded, &MacroExpansionHasCallsite::new())
            .unwrap();
    }
}

fn effect_artifact(
    registry: &AnalysisRegistry<CollectedArtifact>,
    owner_number: u128,
    shape: EffectArtifactShape,
    fault: Option<EffectArtifactFault>,
) -> (ArtifactFactIr, FunctionKey, EffectSiteKey) {
    let owner_key = function(owner_number, None);
    let effect_key = EffectSiteKey::from_mir(
        owner_key,
        MirBodyLocation {
            basic_block: 2,
            statement_index: 5,
        },
    )
    .unwrap();
    let mut builder = ArtifactDbBuilder::new();
    for descriptor in registry.schemas().descriptors() {
        builder.declare_table(descriptor).unwrap();
    }
    let (presentation, expanded) = insert_effect_source_anchors(&mut builder);

    let body = builder
        .insert_entity(&FunctionEntity::new(
            owner_key,
            "crate::effect_owner",
            FunctionBodyProvenance::DefiningArtifact,
        ))
        .unwrap();
    let callable = builder
        .insert_entity(&CallableEntity::new(
            owner_key,
            "crate::effect_owner",
            false,
            false,
            true,
            false,
            vec![String::from("crate::effect_owner")],
        ))
        .unwrap();
    builder
        .relate(&body, &callable, &FunctionDefinesCallable::new())
        .unwrap();
    let effect = builder
        .insert_entity(&EffectSiteEntity::new(effect_key))
        .unwrap();
    if !matches!(fault, Some(EffectArtifactFault::MissingOwner)) {
        builder
            .relate(&body, &effect, &FunctionOwnsEffectSite::new())
            .unwrap();
    }
    if matches!(fault, Some(EffectArtifactFault::DuplicateOwner)) {
        builder
            .relate(&body, &effect, &FunctionOwnsEffectSite::new())
            .unwrap();
    }
    builder
        .relate(
            &effect,
            &presentation,
            &EffectSiteHasSourceAnchor::new(EffectSourceAnchorRole::Presentation),
        )
        .unwrap();
    if matches!(fault, Some(EffectArtifactFault::DuplicateSourceRole)) {
        builder
            .relate(
                &effect,
                &expanded,
                &EffectSiteHasSourceAnchor::new(EffectSourceAnchorRole::Presentation),
            )
            .unwrap();
    }
    builder
        .relate(
            &effect,
            &expanded,
            &EffectSiteHasSourceAnchor::new(EffectSourceAnchorRole::Expanded),
        )
        .unwrap();

    if matches!(shape, EffectArtifactShape::Macro) {
        insert_effect_macro_path(
            &mut builder,
            owner_number,
            fault,
            &body,
            &effect,
            &presentation,
            &expanded,
        );
    }

    (
        builder.finalize(registry.schemas()).unwrap(),
        owner_key,
        effect_key,
    )
}

#[derive(Clone, Copy)]
enum UnsafeArtifactShape {
    Direct,
    DirectWithoutSources,
    Macro,
}

#[derive(Clone, Copy, Debug)]
enum UnsafeArtifactFault {
    MissingOwner,
    DuplicateOwner,
    WrongOwner,
    MissingGroup,
    DuplicateGroup,
    WrongGroup,
    DuplicateSourceRole,
    NoncontiguousMacroDepth,
    MissingMacroEntry,
    DuplicateMacroEntry,
    SurplusMacroEntry,
    MissingMacroLink,
    DuplicateMacroLink,
    ReversedMacroLink,
    MissingMacroExit,
    DuplicateMacroExit,
    DuplicateMacroCallsite,
}

struct UnsafeFixtureEndpoints {
    body: EntityHandle<FunctionEntity>,
    operation: EntityHandle<UnsafeOperationEntity>,
    presentation: EntityHandle<SourceAnchorEntity>,
    expanded: EntityHandle<SourceAnchorEntity>,
}

fn insert_unsafe_macro_relations(
    builder: &mut ArtifactDbBuilder,
    endpoints: &UnsafeFixtureEndpoints,
    outer: &EntityHandle<UnsafeOperationMacroExpansionEntity>,
    inner: &EntityHandle<UnsafeOperationMacroExpansionEntity>,
    fault: Option<UnsafeArtifactFault>,
) {
    if !matches!(fault, Some(UnsafeArtifactFault::MissingMacroEntry)) {
        builder
            .relate(
                &endpoints.body,
                outer,
                &FunctionEntersUnsafeOperationMacroExpansion::new(),
            )
            .unwrap();
    }
    if matches!(fault, Some(UnsafeArtifactFault::SurplusMacroEntry)) {
        builder
            .relate(
                &endpoints.body,
                inner,
                &FunctionEntersUnsafeOperationMacroExpansion::new(),
            )
            .unwrap();
    }
    if matches!(fault, Some(UnsafeArtifactFault::DuplicateMacroEntry)) {
        builder
            .relate(
                &endpoints.body,
                outer,
                &FunctionEntersUnsafeOperationMacroExpansion::new(),
            )
            .unwrap();
    }
    if !matches!(fault, Some(UnsafeArtifactFault::MissingMacroLink)) {
        let (from, to) = if matches!(fault, Some(UnsafeArtifactFault::ReversedMacroLink)) {
            (inner, outer)
        } else {
            (outer, inner)
        };
        builder
            .relate(
                from,
                to,
                &UnsafeOperationMacroExpansionEntersUnsafeOperationMacroExpansion::new(),
            )
            .unwrap();
    }
    if matches!(fault, Some(UnsafeArtifactFault::DuplicateMacroLink)) {
        builder
            .relate(
                outer,
                inner,
                &UnsafeOperationMacroExpansionEntersUnsafeOperationMacroExpansion::new(),
            )
            .unwrap();
    }
    if !matches!(fault, Some(UnsafeArtifactFault::MissingMacroExit)) {
        builder
            .relate(
                inner,
                &endpoints.operation,
                &UnsafeOperationMacroExpansionProducesUnsafeOperation::new(),
            )
            .unwrap();
    }
    if matches!(fault, Some(UnsafeArtifactFault::DuplicateMacroExit)) {
        builder
            .relate(
                inner,
                &endpoints.operation,
                &UnsafeOperationMacroExpansionProducesUnsafeOperation::new(),
            )
            .unwrap();
    }
}

fn insert_unsafe_macro_path(
    builder: &mut ArtifactDbBuilder,
    owner_number: u128,
    endpoints: &UnsafeFixtureEndpoints,
    fault: Option<UnsafeArtifactFault>,
) {
    let operation_key = *endpoints.operation.key();
    // Reverse entity insertion proves semantic depth owns the path.
    let inner_depth = if matches!(fault, Some(UnsafeArtifactFault::NoncontiguousMacroDepth)) {
        2
    } else {
        1
    };
    let inner = builder
        .insert_entity(&UnsafeOperationMacroExpansionEntity::new(
            UnsafeOperationMacroExpansionKey::new(operation_key, inner_depth),
            expansion(owner_number + 1),
            definition(owner_number + 101),
            "crate::inner_unsafe_macro",
        ))
        .unwrap();
    let outer = builder
        .insert_entity(&UnsafeOperationMacroExpansionEntity::new(
            UnsafeOperationMacroExpansionKey::new(operation_key, 0),
            expansion(owner_number),
            definition(owner_number + 100),
            "crate::outer_unsafe_macro",
        ))
        .unwrap();
    insert_unsafe_macro_relations(builder, endpoints, &outer, &inner, fault);
    builder
        .relate(
            &outer,
            &endpoints.presentation,
            &UnsafeOperationMacroExpansionHasCallsite::new(),
        )
        .unwrap();
    if matches!(fault, Some(UnsafeArtifactFault::DuplicateMacroCallsite)) {
        builder
            .relate(
                &outer,
                &endpoints.expanded,
                &UnsafeOperationMacroExpansionHasCallsite::new(),
            )
            .unwrap();
    }
}

fn insert_unsafe_fixture_function(
    builder: &mut ArtifactDbBuilder,
    key: FunctionKey,
    display_path: &str,
) -> EntityHandle<FunctionEntity> {
    let body = builder
        .insert_entity(&FunctionEntity::new(
            key,
            display_path,
            FunctionBodyProvenance::DefiningArtifact,
        ))
        .unwrap();
    let callable = builder
        .insert_entity(&CallableEntity::new(
            key,
            display_path,
            false,
            false,
            true,
            false,
            vec![display_path.to_owned()],
        ))
        .unwrap();
    builder
        .relate(&body, &callable, &FunctionDefinesCallable::new())
        .unwrap();
    body
}

fn insert_unsafe_ownership_fault(
    builder: &mut ArtifactDbBuilder,
    body: &EntityHandle<FunctionEntity>,
    alternate: Option<&(FunctionKey, EntityHandle<FunctionEntity>)>,
    operation: &EntityHandle<UnsafeOperationEntity>,
    fault: Option<UnsafeArtifactFault>,
) {
    if !matches!(fault, Some(UnsafeArtifactFault::MissingOwner)) {
        let owner_endpoint = if matches!(fault, Some(UnsafeArtifactFault::WrongOwner)) {
            &alternate
                .expect("wrong-owner fixture has an alternate body")
                .1
        } else {
            body
        };
        builder
            .relate(
                owner_endpoint,
                operation,
                &FunctionOwnsUnsafeOperation::new(),
            )
            .unwrap();
    }
    if matches!(fault, Some(UnsafeArtifactFault::DuplicateOwner)) {
        builder
            .relate(body, operation, &FunctionOwnsUnsafeOperation::new())
            .unwrap();
    }
}

fn insert_unsafe_group_fault(
    builder: &mut ArtifactDbBuilder,
    group: &EntityHandle<SafetyEffectGroupEntity>,
    alternate: Option<&(FunctionKey, EntityHandle<FunctionEntity>)>,
    operation: &EntityHandle<UnsafeOperationEntity>,
    fault: Option<UnsafeArtifactFault>,
) {
    if !matches!(fault, Some(UnsafeArtifactFault::MissingGroup)) {
        if matches!(fault, Some(UnsafeArtifactFault::WrongGroup)) {
            let (alternate_key, alternate_body) =
                alternate.expect("wrong-group fixture has an alternate body");
            let alternate_group = builder
                .insert_entity(&SafetyEffectGroupEntity::new(SafetyEffectGroupKey::new(
                    *alternate_key,
                    0,
                )))
                .unwrap();
            builder
                .relate(
                    alternate_body,
                    &alternate_group,
                    &FunctionOwnsSafetyEffectGroup::new(),
                )
                .unwrap();
            builder
                .relate(
                    operation,
                    &alternate_group,
                    &UnsafeOperationInSafetyEffectGroup::new(),
                )
                .unwrap();
        } else {
            builder
                .relate(operation, group, &UnsafeOperationInSafetyEffectGroup::new())
                .unwrap();
        }
    }
    if matches!(fault, Some(UnsafeArtifactFault::DuplicateGroup)) {
        builder
            .relate(operation, group, &UnsafeOperationInSafetyEffectGroup::new())
            .unwrap();
    }
}

fn insert_unsafe_source_fault(
    builder: &mut ArtifactDbBuilder,
    shape: UnsafeArtifactShape,
    operation: &EntityHandle<UnsafeOperationEntity>,
    presentation: &EntityHandle<SourceAnchorEntity>,
    expanded: &EntityHandle<SourceAnchorEntity>,
    fault: Option<UnsafeArtifactFault>,
) {
    if !matches!(shape, UnsafeArtifactShape::DirectWithoutSources) {
        // Reverse relation insertion proves semantic role order owns the query.
        builder
            .relate(
                operation,
                expanded,
                &UnsafeOperationHasSourceAnchor::new(UnsafeOperationSourceAnchorRole::Expanded),
            )
            .unwrap();
        builder
            .relate(
                operation,
                presentation,
                &UnsafeOperationHasSourceAnchor::new(UnsafeOperationSourceAnchorRole::Presentation),
            )
            .unwrap();
    }
    if matches!(fault, Some(UnsafeArtifactFault::DuplicateSourceRole)) {
        builder
            .relate(
                operation,
                expanded,
                &UnsafeOperationHasSourceAnchor::new(UnsafeOperationSourceAnchorRole::Presentation),
            )
            .unwrap();
    }
}

fn unsafe_artifact(
    registry: &AnalysisRegistry<CollectedArtifact>,
    owner_number: u128,
    shape: UnsafeArtifactShape,
) -> (ArtifactFactIr, FunctionKey, UnsafeOperationKey) {
    unsafe_artifact_with_fault(registry, owner_number, shape, None)
}

fn unsafe_artifact_with_fault(
    registry: &AnalysisRegistry<CollectedArtifact>,
    owner_number: u128,
    shape: UnsafeArtifactShape,
    fault: Option<UnsafeArtifactFault>,
) -> (ArtifactFactIr, FunctionKey, UnsafeOperationKey) {
    let owner_key = function(owner_number, None);
    let operation_key = UnsafeOperationKey::new(owner_key, 0);
    let mut builder = ArtifactDbBuilder::new();
    for descriptor in registry.schemas().descriptors() {
        builder.declare_table(descriptor).unwrap();
    }
    let (presentation, expanded) = insert_effect_source_anchors(&mut builder);
    let body = insert_unsafe_fixture_function(&mut builder, owner_key, "crate::unsafe_owner");
    let alternate_owner = if matches!(
        fault,
        Some(UnsafeArtifactFault::WrongOwner | UnsafeArtifactFault::WrongGroup)
    ) {
        let alternate_key = function(owner_number + 10_000, None);
        let alternate_body = insert_unsafe_fixture_function(
            &mut builder,
            alternate_key,
            "crate::alternate_unsafe_owner",
        );
        Some((alternate_key, alternate_body))
    } else {
        None
    };
    let group = builder
        .insert_entity(&SafetyEffectGroupEntity::new(SafetyEffectGroupKey::new(
            owner_key, 0,
        )))
        .unwrap();
    builder
        .relate(&body, &group, &FunctionOwnsSafetyEffectGroup::new())
        .unwrap();
    let operation = builder
        .insert_entity(&UnsafeOperationEntity::new(
            operation_key,
            SafetyOperationKind::DerefRawPointer,
        ))
        .unwrap();
    insert_unsafe_ownership_fault(
        &mut builder,
        &body,
        alternate_owner.as_ref(),
        &operation,
        fault,
    );
    insert_unsafe_group_fault(
        &mut builder,
        &group,
        alternate_owner.as_ref(),
        &operation,
        fault,
    );
    insert_unsafe_source_fault(
        &mut builder,
        shape,
        &operation,
        &presentation,
        &expanded,
        fault,
    );

    if matches!(shape, UnsafeArtifactShape::Macro) {
        let endpoints = UnsafeFixtureEndpoints {
            body,
            operation,
            presentation,
            expanded,
        };
        insert_unsafe_macro_path(&mut builder, owner_number, &endpoints, fault);
    }

    (
        builder.finalize(registry.schemas()).unwrap(),
        owner_key,
        operation_key,
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "the malformed-topology fixture keeps every typed endpoint visible in one story"
)]
fn call_artifact(
    registry: &AnalysisRegistry<CollectedArtifact>,
    group_owner: FunctionKey,
    target: FunctionKey,
) -> (ArtifactFactIr, FunctionKey, CallOccurrenceKey) {
    let owner = function(50, Some(51));
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
    let anchor = builder
        .insert_entity(&SourceAnchorEntity::new(SourceAnchorKey::new(
            "src/lib.rs",
            0,
            10,
        )))
        .unwrap();
    builder
        .relate(&anchor, &file, &SourceAnchorInFile::new())
        .unwrap();

    let owner_body = builder
        .insert_entity(&FunctionEntity::new(
            owner,
            "crate::owner",
            FunctionBodyProvenance::DefiningArtifact,
        ))
        .unwrap();
    let owner_callable = builder
        .insert_entity(&CallableEntity::new(
            owner,
            "crate::owner",
            false,
            false,
            true,
            false,
            vec![String::from("crate::owner")],
        ))
        .unwrap();
    builder
        .relate(
            &owner_body,
            &owner_callable,
            &FunctionDefinesCallable::new(),
        )
        .unwrap();
    let target_callable = builder
        .insert_entity(&CallableEntity::new(
            target,
            "crate::target",
            false,
            false,
            false,
            false,
            vec![String::from("crate::target")],
        ))
        .unwrap();

    let group_key = SafetyEffectGroupKey::new(group_owner, 0);
    let group = builder
        .insert_entity(&SafetyEffectGroupEntity::new(group_key))
        .unwrap();
    builder
        .relate(&owner_body, &group, &FunctionOwnsSafetyEffectGroup::new())
        .unwrap();

    let site_key = CallSiteKey::new(owner, 0);
    let site = builder
        .insert_entity(&CallSiteEntity::new(site_key))
        .unwrap();
    builder
        .relate(&owner_body, &site, &FunctionOwnsCallSite::new())
        .unwrap();
    let occurrence_key = CallOccurrenceKey::new(owner, 0);
    let occurrence = builder
        .insert_entity(&CallOccurrenceEntity::new(
            occurrence_key,
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
    builder
        .relate(
            &occurrence,
            &group,
            &CallOccurrenceInSafetyEffectGroup::new(),
        )
        .unwrap();

    (
        builder.finalize(registry.schemas()).unwrap(),
        owner,
        occurrence_key,
    )
}

struct ConfiguredCall {
    kind: CallKind,
    callable_key: Option<CallableKey>,
    runtime_target: Option<FunctionKey>,
    opaque_description: Option<String>,
    malformed_macro_depth: Option<u32>,
    duplicate_presentation_anchors: bool,
    marker_candidate_path_mismatch: Option<bool>,
    duplicate_call_macro_relations: bool,
    duplicate_call_macro_callsites: bool,
}

#[allow(
    clippy::too_many_lines,
    reason = "the callable-evidence fixture keeps the invocation and evidence topology explicit"
)]
fn configured_call_artifact(
    registry: &AnalysisRegistry<CollectedArtifact>,
    owner_number: u128,
    config: ConfiguredCall,
) -> (ArtifactFactIr, CallOccurrenceKey) {
    let owner = function(owner_number, Some(owner_number + 1));
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
    let anchor = builder
        .insert_entity(&SourceAnchorEntity::new(SourceAnchorKey::new(
            "src/lib.rs",
            0,
            10,
        )))
        .unwrap();
    builder
        .relate(&anchor, &file, &SourceAnchorInFile::new())
        .unwrap();

    let body = builder
        .insert_entity(&FunctionEntity::new(
            owner,
            "crate::owner",
            FunctionBodyProvenance::DefiningArtifact,
        ))
        .unwrap();
    let callable = builder
        .insert_entity(&CallableEntity::new(
            owner,
            "crate::owner",
            false,
            false,
            true,
            false,
            vec![String::from("crate::owner")],
        ))
        .unwrap();
    builder
        .relate(&body, &callable, &FunctionDefinesCallable::new())
        .unwrap();
    let group = builder
        .insert_entity(&SafetyEffectGroupEntity::new(SafetyEffectGroupKey::new(
            owner, 0,
        )))
        .unwrap();
    builder
        .relate(&body, &group, &FunctionOwnsSafetyEffectGroup::new())
        .unwrap();
    let site = builder
        .insert_entity(&CallSiteEntity::new(CallSiteKey::new(owner, 0)))
        .unwrap();
    builder
        .relate(&body, &site, &FunctionOwnsCallSite::new())
        .unwrap();
    let occurrence_key = CallOccurrenceKey::new(owner, 0);
    let occurrence = builder
        .insert_entity(&CallOccurrenceEntity::new(
            occurrence_key,
            config.kind,
            vec![CallAttributionRole::CallSite],
            false,
            false,
            config.opaque_description,
        ))
        .unwrap();
    builder
        .relate(&site, &occurrence, &CallSiteHasOccurrence::new())
        .unwrap();
    builder
        .relate(
            &occurrence,
            &group,
            &CallOccurrenceInSafetyEffectGroup::new(),
        )
        .unwrap();

    if let Some(target) = config.runtime_target {
        let target = builder
            .insert_entity(&CallableEntity::new(
                target,
                "crate::target",
                false,
                false,
                false,
                false,
                vec![String::from("crate::target")],
            ))
            .unwrap();
        builder
            .relate(
                &occurrence,
                &target,
                &CallOccurrenceTargetsCallable::new(CallTargetRole::Runtime),
            )
            .unwrap();
    }
    if let Some(key) = config.callable_key {
        let key = builder.insert_entity(&CallableKeyEntity::new(key)).unwrap();
        builder
            .relate(&occurrence, &key, &CallOccurrenceHasCallableKey::new())
            .unwrap();
    }
    if let Some(depth) = config.malformed_macro_depth {
        builder
            .insert_entity(&CallMacroExpansionEntity::new(
                CallMacroExpansionKey::new(occurrence_key, depth),
                expansion(owner_number),
                definition(owner_number),
                "crate::macro",
            ))
            .unwrap();
    }
    if config.duplicate_presentation_anchors {
        let second_anchor = builder
            .insert_entity(&SourceAnchorEntity::new(SourceAnchorKey::new(
                "src/lib.rs",
                10,
                20,
            )))
            .unwrap();
        builder
            .relate(&second_anchor, &file, &SourceAnchorInFile::new())
            .unwrap();
        for source in [&anchor, &second_anchor] {
            builder
                .relate(
                    &occurrence,
                    source,
                    &CallOccurrenceHasSourceAnchor::new(CallSourceAnchorRole::Presentation),
                )
                .unwrap();
        }
    } else {
        for role in [
            CallSourceAnchorRole::Presentation,
            CallSourceAnchorRole::Expanded,
            CallSourceAnchorRole::Callee,
        ] {
            builder
                .relate(
                    &occurrence,
                    &anchor,
                    &CallOccurrenceHasSourceAnchor::new(role),
                )
                .unwrap();
        }
    }
    if let Some(path_mismatch) = config.marker_candidate_path_mismatch {
        let outer_frame = builder
            .insert_entity(&CallMacroExpansionEntity::new(
                CallMacroExpansionKey::new(occurrence_key, 0),
                expansion(owner_number),
                definition(owner_number),
                "crate::call_macro",
            ))
            .unwrap();
        let inner_frame = builder
            .insert_entity(&CallMacroExpansionEntity::new(
                CallMacroExpansionKey::new(occurrence_key, 1),
                expansion(owner_number + 1),
                definition(owner_number),
                "crate::inner_macro",
            ))
            .unwrap();
        let relation_copies = if config.duplicate_call_macro_relations {
            2
        } else {
            1
        };
        for _ in 0..relation_copies {
            builder
                .relate(
                    &body,
                    &outer_frame,
                    &FunctionEntersCallMacroExpansion::new(),
                )
                .unwrap();
            builder
                .relate(
                    &outer_frame,
                    &inner_frame,
                    &CallMacroExpansionEntersCallMacroExpansion::new(),
                )
                .unwrap();
            builder
                .relate(
                    &inner_frame,
                    &occurrence,
                    &CallMacroExpansionProducesCallOccurrence::new(),
                )
                .unwrap();
        }
        builder
            .relate(&outer_frame, &anchor, &CallMacroExpansionHasCallsite::new())
            .unwrap();
        if config.duplicate_call_macro_callsites {
            let second_callsite = builder
                .insert_entity(&SourceAnchorEntity::new(SourceAnchorKey::new(
                    "src/lib.rs",
                    40,
                    50,
                )))
                .unwrap();
            builder
                .relate(&second_callsite, &file, &SourceAnchorInFile::new())
                .unwrap();
            builder
                .relate(
                    &outer_frame,
                    &second_callsite,
                    &CallMacroExpansionHasCallsite::new(),
                )
                .unwrap();
        }

        let marker_hash = expansion(if path_mismatch {
            owner_number + 1_000
        } else {
            owner_number
        });
        let marker_key =
            MarkerOccurrenceKey::new(SourceAnchorKey::new("src/lib.rs", 0, 10), Some(marker_hash));
        let marker = builder
            .insert_entity(&MarkerOccurrenceEntity::new(
                marker_key.clone(),
                vec![marker_hash],
            ))
            .unwrap();
        builder
            .relate(&marker, &anchor, &MarkerOccurrenceHasSourceAnchor::new())
            .unwrap();
        let claim = builder
            .insert_entity(&MarkerClaimEntity::new(
                MarkerClaimKey::new(marker_key, DomainId::new("sniff-test.safety").unwrap(), 0),
                EvidenceClaimSelector::Unnamed,
                "validated rationale",
            ))
            .unwrap();
        builder
            .relate(&marker, &claim, &MarkerOccurrenceHasClaim::new())
            .unwrap();
        builder
            .relate(
                &occurrence,
                &claim,
                &CallOccurrenceHasMarkerClaimCandidate::new(true, false),
            )
            .unwrap();
    }

    (
        builder.finalize(registry.schemas()).unwrap(),
        occurrence_key,
    )
}

struct CallableEvidenceArtifacts {
    key: CallableKey,
    invocation: ArtifactFactIr,
    invocation_key: CallOccurrenceKey,
    reachable: ArtifactFactIr,
    reachable_key: CallOccurrenceKey,
    reachable_callable: FunctionKey,
    unreachable: ArtifactFactIr,
}

fn callable_evidence_artifacts(
    registry: &AnalysisRegistry<CollectedArtifact>,
) -> CallableEvidenceArtifacts {
    let key = CallableKey::DynDispatch(definition(500));
    let (invocation, invocation_key) = configured_call_artifact(
        registry,
        100,
        ConfiguredCall {
            kind: CallKind::IndirectCall,
            callable_key: Some(key),
            runtime_target: None,
            opaque_description: Some(String::from("dynamic invocation")),
            malformed_macro_depth: None,
            duplicate_presentation_anchors: false,
            marker_candidate_path_mismatch: None,
            duplicate_call_macro_relations: false,
            duplicate_call_macro_callsites: false,
        },
    );
    let reachable_callable = function(200, Some(201));
    let (reachable, reachable_key) = configured_call_artifact(
        registry,
        110,
        ConfiguredCall {
            kind: CallKind::VTableEntry,
            callable_key: Some(key),
            runtime_target: Some(reachable_callable),
            opaque_description: None,
            malformed_macro_depth: None,
            duplicate_presentation_anchors: false,
            marker_candidate_path_mismatch: None,
            duplicate_call_macro_relations: false,
            duplicate_call_macro_callsites: false,
        },
    );
    let (unreachable, _) = configured_call_artifact(
        registry,
        120,
        ConfiguredCall {
            kind: CallKind::VTableEntry,
            callable_key: Some(key),
            runtime_target: Some(function(300, Some(301))),
            opaque_description: None,
            malformed_macro_depth: None,
            duplicate_presentation_anchors: false,
            marker_candidate_path_mismatch: None,
            duplicate_call_macro_relations: false,
            duplicate_call_macro_callsites: false,
        },
    );
    CallableEvidenceArtifacts {
        key,
        invocation,
        invocation_key,
        reachable,
        reachable_key,
        reachable_callable,
        unreachable,
    }
}

#[test]
fn core_pack_registers_the_four_strict_root_composition_schemas() {
    fn assert_relation<R: RelationSchema>() {}

    assert_relation::<CallableSelectsFunctionBody>();
    assert_relation::<CallableInvocationTargetsCallable>();
    assert_relation::<ConsumerOverlayUsesDefiningSourceBody>();
    assert_relation::<ConsumerOccurrenceReconcilesWith>();

    let mut registry = AnalysisRegistry::<()>::new();
    registry.install(&CoreProgramPack).unwrap();

    let schemas = registry.composition_relations();
    let selection = schemas
        .descriptor_for::<CallableSelectsFunctionBody>()
        .unwrap();
    assert_eq!(selection.version(), 1);
    assert_eq!(selection.from().as_str(), CallableEntity::ID);
    assert_eq!(selection.to().as_str(), FunctionEntity::ID);

    let invocation = schemas
        .descriptor_for::<CallableInvocationTargetsCallable>()
        .unwrap();
    assert_eq!(invocation.from().as_str(), CallOccurrenceEntity::ID);
    assert_eq!(invocation.to().as_str(), CallableEntity::ID);

    let overlay = schemas
        .descriptor_for::<ConsumerOverlayUsesDefiningSourceBody>()
        .unwrap();
    assert_eq!(overlay.from().as_str(), FunctionEntity::ID);
    assert_eq!(overlay.to().as_str(), FunctionEntity::ID);

    let reconciliation = schemas
        .descriptor_for::<ConsumerOccurrenceReconcilesWith>()
        .unwrap();
    assert_eq!(reconciliation.from().as_str(), CallOccurrenceEntity::ID);
    assert_eq!(reconciliation.to().as_str(), CallOccurrenceEntity::ID);
}

#[test]
fn composition_payloads_are_strict_pack_local_semantics() {
    assert_eq!(
        serde_json::to_value(CallableSelectsFunctionBody::new(
            CallableBodySelectionKind::ExactPreferred,
        ))
        .unwrap(),
        json!({ "selection-kind": "exact-preferred" })
    );
    assert_eq!(
        serde_json::to_value(ConsumerOverlayUsesDefiningSourceBody::new()).unwrap(),
        json!({})
    );
    assert_eq!(
        serde_json::to_value(ConsumerOccurrenceReconcilesWith::new(
            ConsumerOccurrenceReconciliationKind::SourceFallback,
        ))
        .unwrap(),
        json!({ "reconciliation-kind": "source-fallback" })
    );
    assert!(
        serde_json::from_value::<CallableSelectsFunctionBody>(json!({
            "selection-kind": "future-selection"
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<ConsumerOccurrenceReconcilesWith>(json!({
            "reconciliation-kind": "semantic-target",
            "future-field": true
        }))
        .is_err()
    );
}

#[test]
fn callable_resolution_kind_must_agree_with_the_callable_key() {
    let pointer = CallableKey::FnPointer(type_hash(1));
    let dynamic = CallableKey::DynDispatch(definition(2));

    let valid = CallableInvocationTargetsCallable::try_new(
        pointer,
        CallableResolutionKind::FunctionPointerEvidence,
    )
    .unwrap();
    assert_eq!(valid.callable_key(), pointer);
    assert_eq!(
        valid.resolution_kind(),
        CallableResolutionKind::FunctionPointerEvidence
    );
    assert_eq!(
        serde_json::to_value(valid).unwrap(),
        json!({
            "callable-key": {
                "kind": "fn-pointer",
                "identity": "00000000000000000000000000000001"
            },
            "resolution-kind": "function-pointer-evidence"
        })
    );

    assert!(
        CallableInvocationTargetsCallable::try_new(
            dynamic,
            CallableResolutionKind::FunctionPointerEvidence,
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<CallableInvocationTargetsCallable>(json!({
            "callable-key": {
                "kind": "dyn-dispatch",
                "identity": "00000000000000000000000000000002"
            },
            "resolution-kind": "function-pointer-evidence"
        }))
        .is_err()
    );
}

#[test]
fn exact_function_keys_remain_separate_across_generations_and_input_order() {
    let registry = artifact_registry();
    let shared = function(10, Some(11));
    let artifact = program_artifact(
        &registry,
        &[(shared, FunctionBodyProvenance::DefiningArtifact)],
    );
    let alpha = scope("workspace.alpha");
    let beta = scope("workspace.beta");
    let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();

    let forward =
        WorkspaceFactView::compose([(alpha.clone(), view), (beta.clone(), view)]).unwrap();
    let reversed =
        WorkspaceFactView::compose([(beta.clone(), view), (alpha.clone(), view)]).unwrap();
    let owners = [verified(&alpha, 0), verified(&beta, 0)];
    let forward_index = WorkspaceProgramIndex::open(&forward, owners.clone()).unwrap();
    let reversed_index = WorkspaceProgramIndex::open(&reversed, owners).unwrap();

    let alpha_body = forward_index.exact_function(&alpha, &shared).unwrap();
    let beta_body = forward_index.exact_function(&beta, &shared).unwrap();
    assert_ne!(alpha_body.reference(), beta_body.reference());
    assert_eq!(
        forward_index.scopes().collect::<Vec<_>>(),
        reversed_index.scopes().collect::<Vec<_>>()
    );
}

#[test]
fn exact_to_generic_candidates_never_escape_the_selected_scope() {
    let registry = artifact_registry();
    let generic = function(20, None);
    let exact = function(20, Some(21));
    let selected_artifact = program_artifact(
        &registry,
        &[
            (generic, FunctionBodyProvenance::DefiningArtifact),
            (exact, FunctionBodyProvenance::DefiningArtifact),
        ],
    );
    let unrelated_artifact = program_artifact(
        &registry,
        &[(exact, FunctionBodyProvenance::DefiningArtifact)],
    );
    let selected = scope("workspace.selected");
    let unrelated = scope("workspace.unrelated");
    let workspace = WorkspaceFactView::compose([
        (
            unrelated.clone(),
            ArtifactDbView::open(&unrelated_artifact, registry.schemas()).unwrap(),
        ),
        (
            selected.clone(),
            ArtifactDbView::open(&selected_artifact, registry.schemas()).unwrap(),
        ),
    ])
    .unwrap();
    let index = WorkspaceProgramIndex::open(
        &workspace,
        [verified(&selected, 0), verified(&unrelated, 0)],
    )
    .unwrap();

    let candidates = index.body_candidates(&selected, &exact).unwrap();
    assert_eq!(candidates.len(), 2);
    assert_eq!(
        candidates
            .iter()
            .map(FunctionBodyCandidate::selection_kind)
            .collect::<Vec<_>>(),
        vec![
            CallableBodySelectionKind::ExactPreferred,
            CallableBodySelectionKind::GenericPreferred,
        ]
    );
    assert!(
        candidates
            .iter()
            .all(|candidate| candidate.body().reference().scope() == &selected)
    );
    assert_eq!(candidates[0].body().data().key(), &exact);
    assert_eq!(candidates[1].body().data().key(), &generic);
}

#[test]
fn defining_body_candidates_require_an_explicit_defining_scope() {
    let registry = artifact_registry();
    let generic = function(30, None);
    let exact = function(30, Some(31));
    let consumer_artifact = program_artifact(
        &registry,
        &[(
            exact,
            FunctionBodyProvenance::ConsumerInstantiation {
                consumer_stable_crate_id: 9,
            },
        )],
    );
    let defining_artifact = program_artifact(
        &registry,
        &[
            (generic, FunctionBodyProvenance::DefiningArtifact),
            (exact, FunctionBodyProvenance::DefiningArtifact),
        ],
    );
    let consumer = scope("workspace.consumer");
    let defining = scope("workspace.defining");
    let workspace = WorkspaceFactView::compose([
        (
            consumer.clone(),
            ArtifactDbView::open(&consumer_artifact, registry.schemas()).unwrap(),
        ),
        (
            defining.clone(),
            ArtifactDbView::open(&defining_artifact, registry.schemas()).unwrap(),
        ),
    ])
    .unwrap();
    let index =
        WorkspaceProgramIndex::open(&workspace, [verified(&consumer, 9), verified(&defining, 0)])
            .unwrap();
    let candidates = index
        .defining_body_candidates(&consumer, &exact, &defining)
        .unwrap();
    assert_eq!(
        candidates
            .iter()
            .map(FunctionBodyCandidate::selection_kind)
            .collect::<Vec<_>>(),
        vec![
            CallableBodySelectionKind::ExactDefining,
            CallableBodySelectionKind::GenericDefining,
        ]
    );
    assert!(candidates.iter().all(|candidate| {
        candidate.body().data().provenance() == FunctionBodyProvenance::DefiningArtifact
            && candidate.body().reference().scope() == &defining
    }));
}

#[test]
fn managed_body_candidates_need_only_the_explicit_defining_scope() {
    let registry = artifact_registry();
    let generic = function(32, None);
    let exact = function(32, Some(33));
    let artifact = program_artifact(
        &registry,
        &[
            (generic, FunctionBodyProvenance::DefiningArtifact),
            (exact, FunctionBodyProvenance::DefiningArtifact),
        ],
    );
    let defining = scope("workspace.managed-defining");
    let workspace = WorkspaceFactView::compose([(
        defining.clone(),
        ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
    )])
    .unwrap();
    let index = WorkspaceProgramIndex::open(&workspace, [verified(&defining, 0)]).unwrap();

    let candidates = index.managed_body_candidates(&defining, &exact).unwrap();
    assert_eq!(
        candidates
            .iter()
            .map(FunctionBodyCandidate::selection_kind)
            .collect::<Vec<_>>(),
        [
            CallableBodySelectionKind::ExactDefining,
            CallableBodySelectionKind::GenericDefining,
        ]
    );
    assert!(candidates.iter().all(|candidate| {
        candidate.body().data().provenance() == FunctionBodyProvenance::DefiningArtifact
            && candidate.body().reference().scope() == &defining
    }));
}

#[test]
fn equal_consumer_overlays_remain_isolated_by_exact_scope() {
    let registry = artifact_registry();
    let exact = function(35, Some(36));
    let consumer_artifact = program_artifact(
        &registry,
        &[(
            exact,
            FunctionBodyProvenance::ConsumerInstantiation {
                consumer_stable_crate_id: 11,
            },
        )],
    );
    let first_scope = scope("workspace.consumer-one");
    let second_scope = scope("workspace.consumer-two");
    let view = ArtifactDbView::open(&consumer_artifact, registry.schemas()).unwrap();
    let workspace =
        WorkspaceFactView::compose([(second_scope.clone(), view), (first_scope.clone(), view)])
            .unwrap();
    let index = WorkspaceProgramIndex::open(
        &workspace,
        [verified(&first_scope, 11), verified(&second_scope, 11)],
    )
    .unwrap();

    let first = index.exact_function(&first_scope, &exact).unwrap();
    let second = index.exact_function(&second_scope, &exact).unwrap();
    assert_ne!(first.reference(), second.reference());
    assert_eq!(first.reference().scope(), &first_scope);
    assert_eq!(second.reference().scope(), &second_scope);
}

#[test]
fn prepared_queries_reject_replacement_workspaces_even_with_equal_scope_strings() {
    let registry = artifact_registry();
    let key = function(40, None);
    let artifact = program_artifact(
        &registry,
        &[(key, FunctionBodyProvenance::DefiningArtifact)],
    );
    let exact_scope = scope("workspace.same-scope");
    let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
    let first = WorkspaceFactView::compose([(exact_scope.clone(), view)]).unwrap();
    let replacement = WorkspaceFactView::compose([(exact_scope.clone(), view)]).unwrap();
    let index = WorkspaceProgramIndex::open(&first, [verified(&exact_scope, 0)]).unwrap();

    assert!(index.query(&first, [exact_scope.clone()]).is_ok());
    assert!(matches!(
        index.query(&replacement, [exact_scope]),
        Err(WorkspaceProgramIndexError::WorkspaceMismatch)
    ));
}

#[test]
fn exact_call_candidate_sets_retain_typed_target_roles_and_ownership() {
    let registry = artifact_registry();
    let target = function(60, Some(61));
    let (artifact, owner, occurrence) = call_artifact(&registry, function(50, Some(51)), target);
    let artifact_scope = scope("workspace.calls");
    let workspace = WorkspaceFactView::compose([(
        artifact_scope.clone(),
        ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
    )])
    .unwrap();
    let index = WorkspaceProgramIndex::open(&workspace, [verified(&artifact_scope, 0)]).unwrap();
    let owner_entity = index.exact_function(&artifact_scope, &owner).unwrap();
    let site_key = CallSiteKey::new(owner, 0);
    let site_entity = index.exact_call_site(&artifact_scope, &site_key).unwrap();
    let occurrence_entity = index
        .exact_call_occurrence(&artifact_scope, &occurrence)
        .unwrap();
    let target_entity = index.exact_callable(&artifact_scope, &target).unwrap();
    assert_eq!(owner_entity.id().erase(), owner_entity.reference().clone());

    assert_eq!(
        index.call_sites_owned_by(&artifact_scope, &owner).unwrap(),
        &[CallSiteKey::new(owner, 0)]
    );
    let site_edges = index
        .call_site_edges_owned_by(&artifact_scope, &owner)
        .unwrap();
    assert_eq!(site_edges.len(), 1);
    assert_eq!(site_edges[0].site(), site_key);
    assert_scoped_relation::<FunctionOwnsCallSite>(site_edges[0].relation(), &artifact_scope);
    assert_relation_endpoints(
        &workspace,
        site_edges[0].relation(),
        owner_entity.reference(),
        site_entity.reference(),
    );
    assert_eq!(
        index
            .call_occurrences_at(&artifact_scope, &CallSiteKey::new(owner, 0))
            .unwrap(),
        &[occurrence]
    );
    let occurrence_edges = index
        .call_occurrence_edges_at(&artifact_scope, &CallSiteKey::new(owner, 0))
        .unwrap();
    assert_eq!(occurrence_edges.len(), 1);
    assert_eq!(occurrence_edges[0].occurrence(), occurrence);
    assert_scoped_relation::<CallSiteHasOccurrence>(
        occurrence_edges[0].relation(),
        &artifact_scope,
    );
    assert_relation_endpoints(
        &workspace,
        occurrence_edges[0].relation(),
        site_entity.reference(),
        occurrence_entity.reference(),
    );
    let targets = index.call_targets(&artifact_scope, &occurrence).unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].role(), CallTargetRole::Runtime);
    assert_eq!(targets[0].callable(), target);
    assert_scoped_relation::<CallOccurrenceTargetsCallable>(targets[0].relation(), &artifact_scope);
    assert_relation_endpoints(
        &workspace,
        targets[0].relation(),
        occurrence_entity.reference(),
        target_entity.reference(),
    );
    assert!(
        index
            .call_macro_path(&artifact_scope, &occurrence)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        index
            .occurrence_safety_group(&artifact_scope, &occurrence)
            .unwrap(),
        &SafetyEffectGroupKey::new(owner, 0)
    );
}

#[test]
fn malformed_target_and_group_topology_is_rejected_at_preparation() {
    let registry = artifact_registry();
    let generic_target = function(70, None);
    let (bad_target, _, _) = call_artifact(&registry, function(50, Some(51)), generic_target);
    let bad_group_owner = function(80, Some(81));
    let (bad_group, _, _) = call_artifact(&registry, bad_group_owner, function(70, Some(71)));

    for (id, artifact) in [
        ("workspace.bad-target", bad_target),
        ("workspace.bad-group", bad_group),
    ] {
        let exact_scope = scope(id);
        let workspace = WorkspaceFactView::compose([(
            exact_scope.clone(),
            ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
        )])
        .unwrap();
        assert!(matches!(
            WorkspaceProgramIndex::open(&workspace, [verified(&exact_scope, 0)]),
            Err(WorkspaceProgramIndexError::MalformedTopology { .. })
        ));
    }
}

#[test]
fn callable_evidence_candidates_are_limited_to_the_branded_reachable_query() {
    let registry = artifact_registry();
    let artifacts = callable_evidence_artifacts(&registry);
    let invocation_scope = scope("workspace.invocation");
    let same_coordinate_scope = scope("workspace.same-invocation-coordinate");
    let reachable_scope = scope("workspace.reachable-evidence");
    let unreachable_scope = scope("workspace.unreachable-evidence");
    let workspace = WorkspaceFactView::compose([
        (
            unreachable_scope.clone(),
            ArtifactDbView::open(&artifacts.unreachable, registry.schemas()).unwrap(),
        ),
        (
            reachable_scope.clone(),
            ArtifactDbView::open(&artifacts.reachable, registry.schemas()).unwrap(),
        ),
        (
            invocation_scope.clone(),
            ArtifactDbView::open(&artifacts.invocation, registry.schemas()).unwrap(),
        ),
        (
            same_coordinate_scope.clone(),
            ArtifactDbView::open(&artifacts.invocation, registry.schemas()).unwrap(),
        ),
    ])
    .unwrap();
    let index = WorkspaceProgramIndex::open(
        &workspace,
        [
            verified(&invocation_scope, 0),
            verified(&same_coordinate_scope, 0),
            verified(&reachable_scope, 0),
            verified(&unreachable_scope, 0),
        ],
    )
    .unwrap();
    assert_eq!(index.stable_crate_id(&invocation_scope).unwrap(), 0);
    assert_eq!(
        index
            .callable_keys(&invocation_scope, &artifacts.invocation_key)
            .unwrap(),
        &[artifacts.key]
    );
    let query = index
        .query(
            &workspace,
            [invocation_scope.clone(), reachable_scope.clone()],
        )
        .unwrap();
    let candidates = query
        .callable_evidence_candidates(&invocation_scope, &artifacts.invocation_key)
        .unwrap();
    let invocation = index
        .exact_call_occurrence(&invocation_scope, &artifacts.invocation_key)
        .unwrap();
    let evidence = index
        .exact_call_occurrence(&reachable_scope, &artifacts.reachable_key)
        .unwrap();
    let callable = index
        .exact_callable(&reachable_scope, &artifacts.reachable_callable)
        .unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].invocation(), &invocation.id());
    assert_eq!(candidates[0].evidence_occurrence(), &evidence.id());
    assert_eq!(candidates[0].callable(), &callable.id());
    assert_eq!(candidates[0].callable().scope(), &reachable_scope);
    assert_ne!(candidates[0].callable().scope(), &unreachable_scope);
    assert_eq!(candidates[0].callable_key(), artifacts.key);
    assert_eq!(
        candidates[0].resolution_kind(),
        CallableResolutionKind::DynamicDispatchEvidence
    );

    let invocation_only = index.query(&workspace, [invocation_scope.clone()]).unwrap();
    assert!(
        invocation_only
            .callable_evidence_candidates(&invocation_scope, &artifacts.invocation_key)
            .unwrap()
            .is_empty()
    );
    let evidence_only = index.query(&workspace, [reachable_scope]).unwrap();
    assert!(matches!(
        evidence_only.callable_evidence_candidates(&invocation_scope, &artifacts.invocation_key),
        Err(WorkspaceProgramIndexError::InvalidQuery { .. })
    ));
    assert!(matches!(
        query.callable_evidence_candidates(&same_coordinate_scope, &artifacts.invocation_key),
        Err(WorkspaceProgramIndexError::InvalidQuery { .. })
    ));
}

#[test]
fn callable_evidence_query_is_empty_when_the_workspace_has_no_evidence_bucket() {
    let registry = artifact_registry();
    let artifacts = callable_evidence_artifacts(&registry);
    let invocation_scope = scope("workspace.invocation-only");
    let workspace = WorkspaceFactView::compose([(
        invocation_scope.clone(),
        ArtifactDbView::open(&artifacts.invocation, registry.schemas()).unwrap(),
    )])
    .unwrap();
    let index = WorkspaceProgramIndex::open(&workspace, [verified(&invocation_scope, 0)]).unwrap();
    let query = index.query(&workspace, [invocation_scope.clone()]).unwrap();

    assert!(
        query
            .callable_evidence_candidates(&invocation_scope, &artifacts.invocation_key)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn noncontiguous_call_macro_paths_are_rejected_at_preparation() {
    let registry = artifact_registry();
    let (artifact, _) = configured_call_artifact(
        &registry,
        600,
        ConfiguredCall {
            kind: CallKind::IndirectCall,
            callable_key: None,
            runtime_target: None,
            opaque_description: Some(String::from("opaque invocation")),
            malformed_macro_depth: Some(1),
            duplicate_presentation_anchors: false,
            marker_candidate_path_mismatch: None,
            duplicate_call_macro_relations: false,
            duplicate_call_macro_callsites: false,
        },
    );
    let exact_scope = scope("workspace.bad-call-macro");
    let workspace = WorkspaceFactView::compose([(
        exact_scope.clone(),
        ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
    )])
    .unwrap();

    assert!(matches!(
        WorkspaceProgramIndex::open(&workspace, [verified(&exact_scope, 0)]),
        Err(WorkspaceProgramIndexError::MalformedTopology { .. })
    ));
}

#[test]
fn duplicate_call_macro_structural_relations_are_rejected() {
    let registry = artifact_registry();
    let (artifact, _) = configured_call_artifact(
        &registry,
        605,
        ConfiguredCall {
            kind: CallKind::IndirectCall,
            callable_key: None,
            runtime_target: None,
            opaque_description: Some(String::from("opaque invocation")),
            malformed_macro_depth: None,
            duplicate_presentation_anchors: false,
            marker_candidate_path_mismatch: Some(false),
            duplicate_call_macro_relations: true,
            duplicate_call_macro_callsites: false,
        },
    );
    let exact_scope = scope("workspace.duplicate-call-macro-relations");
    let workspace = WorkspaceFactView::compose([(
        exact_scope.clone(),
        ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
    )])
    .unwrap();

    assert!(matches!(
        WorkspaceProgramIndex::open(&workspace, [verified(&exact_scope, 0)]),
        Err(WorkspaceProgramIndexError::MalformedTopology { .. })
    ));
}

#[test]
fn call_source_anchor_roles_are_unique_per_occurrence() {
    let registry = artifact_registry();
    let (artifact, _) = configured_call_artifact(
        &registry,
        610,
        ConfiguredCall {
            kind: CallKind::IndirectCall,
            callable_key: None,
            runtime_target: None,
            opaque_description: Some(String::from("opaque invocation")),
            malformed_macro_depth: None,
            duplicate_presentation_anchors: true,
            marker_candidate_path_mismatch: None,
            duplicate_call_macro_relations: false,
            duplicate_call_macro_callsites: false,
        },
    );
    let exact_scope = scope("workspace.bad-call-source-role");
    let workspace = WorkspaceFactView::compose([(
        exact_scope.clone(),
        ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
    )])
    .unwrap();

    assert!(matches!(
        WorkspaceProgramIndex::open(&workspace, [verified(&exact_scope, 0)]),
        Err(WorkspaceProgramIndexError::MalformedTopology { .. })
    ));
}

#[test]
fn call_source_anchor_roles_retain_exact_typed_anchors_and_relations() {
    let registry = artifact_registry();
    let (artifact, occurrence) = configured_call_artifact(
        &registry,
        615,
        ConfiguredCall {
            kind: CallKind::IndirectCall,
            callable_key: None,
            runtime_target: None,
            opaque_description: Some(String::from("opaque invocation")),
            malformed_macro_depth: None,
            duplicate_presentation_anchors: false,
            marker_candidate_path_mismatch: None,
            duplicate_call_macro_relations: false,
            duplicate_call_macro_callsites: false,
        },
    );
    let exact_scope = scope("workspace.call-source-anchors");
    let workspace = WorkspaceFactView::compose([(
        exact_scope.clone(),
        ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
    )])
    .unwrap();
    let index = WorkspaceProgramIndex::open(&workspace, [verified(&exact_scope, 0)]).unwrap();
    let anchor_key = SourceAnchorKey::new("src/lib.rs", 0, 10);
    let anchor = index
        .exact_source_anchor(&exact_scope, &anchor_key)
        .unwrap();
    let occurrence_entity = index
        .exact_call_occurrence(&exact_scope, &occurrence)
        .unwrap();
    let artifact_view = workspace.artifact(&exact_scope).unwrap();

    let sources = index
        .call_source_anchors(&exact_scope, &occurrence)
        .unwrap();
    assert_eq!(sources.len(), 3);
    assert_eq!(
        sources
            .iter()
            .map(super::topology::IndexedCallSourceAnchor::role)
            .collect::<Vec<_>>(),
        [
            CallSourceAnchorRole::Presentation,
            CallSourceAnchorRole::Expanded,
            CallSourceAnchorRole::Callee,
        ]
    );
    for source in sources {
        assert_eq!(source.anchor(), &anchor.id());
        assert_eq!(source.anchor_key(), &anchor_key);
        assert_scoped_relation::<CallOccurrenceHasSourceAnchor>(source.relation(), &exact_scope);
        assert_relation_endpoints(
            &workspace,
            source.relation(),
            occurrence_entity.reference(),
            anchor.reference(),
        );
        let relation = artifact_view
            .relation::<CallOccurrenceHasSourceAnchor>(source.relation().relation().row)
            .unwrap();
        assert_eq!(relation.data.role(), source.role());
    }
}

#[test]
fn effect_topology_retains_exact_ownership_and_sources() {
    let registry = artifact_registry();
    let (artifact, function_key, effect) =
        effect_artifact(&registry, 617, EffectArtifactShape::Macro, None);
    let exact_scope = scope("workspace.effect-ownership-sources");
    let workspace = WorkspaceFactView::compose([(
        exact_scope.clone(),
        ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
    )])
    .unwrap();
    let index = WorkspaceProgramIndex::open(&workspace, [verified(&exact_scope, 0)]).unwrap();
    let body = index.exact_function(&exact_scope, &function_key).unwrap();
    let effect_entity = index.exact_effect_site(&exact_scope, &effect).unwrap();

    let ownership_edges = index
        .effect_site_edges_owned_by(&exact_scope, &function_key)
        .unwrap();
    assert_eq!(ownership_edges.len(), 1);
    assert_eq!(ownership_edges[0].site(), effect);
    assert_eq!(ownership_edges[0].effect(), &effect_entity.id());
    assert_scoped_relation::<FunctionOwnsEffectSite>(ownership_edges[0].relation(), &exact_scope);
    assert_relation_endpoints(
        &workspace,
        ownership_edges[0].relation(),
        body.reference(),
        effect_entity.reference(),
    );

    let sources = index.effect_source_anchors(&exact_scope, &effect).unwrap();
    assert_eq!(sources.len(), 2);
    assert_eq!(sources[0].role(), EffectSourceAnchorRole::Presentation);
    assert_eq!(sources[1].role(), EffectSourceAnchorRole::Expanded);
    for source in sources {
        let anchor = index
            .exact_source_anchor(&exact_scope, source.anchor_key())
            .unwrap();
        assert_eq!(source.anchor(), &anchor.id());
        assert_scoped_relation::<EffectSiteHasSourceAnchor>(source.relation(), &exact_scope);
        assert_relation_endpoints(
            &workspace,
            source.relation(),
            effect_entity.reference(),
            anchor.reference(),
        );
    }
}

#[test]
fn effect_macro_path_retains_exact_frames_relations_and_callsites() {
    let registry = artifact_registry();
    let (artifact, function_key, effect) =
        effect_artifact(&registry, 619, EffectArtifactShape::Macro, None);
    let exact_scope = scope("workspace.effect-macro-path");
    let workspace = WorkspaceFactView::compose([(
        exact_scope.clone(),
        ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
    )])
    .unwrap();
    let index = WorkspaceProgramIndex::open(&workspace, [verified(&exact_scope, 0)]).unwrap();
    let body = index.exact_function(&exact_scope, &function_key).unwrap();
    let effect_entity = index.exact_effect_site(&exact_scope, &effect).unwrap();

    let path = index
        .effect_macro_path(&exact_scope, &effect)
        .unwrap()
        .expect("macro effect has an exact path");
    assert_eq!(
        path.frames()
            .iter()
            .map(|frame| frame.data().expansion().depth())
            .collect::<Vec<_>>(),
        [0, 1]
    );
    for frame in path.frames() {
        assert_eq!(
            frame.id(),
            index
                .exact_effect_macro(&exact_scope, frame.data().expansion())
                .unwrap()
                .id()
        );
    }
    assert_scoped_relation::<FunctionEntersMacroExpansion>(path.entry(), &exact_scope);
    assert_relation_endpoints(
        &workspace,
        path.entry(),
        body.reference(),
        path.frames()[0].reference(),
    );
    assert_eq!(path.links().len(), 1);
    assert_scoped_relation::<MacroExpansionEntersMacroExpansion>(&path.links()[0], &exact_scope);
    assert_relation_endpoints(
        &workspace,
        &path.links()[0],
        path.frames()[0].reference(),
        path.frames()[1].reference(),
    );
    assert_scoped_relation::<MacroExpansionProducesEffectSite>(path.exit(), &exact_scope);
    assert_relation_endpoints(
        &workspace,
        path.exit(),
        path.frames()[1].reference(),
        effect_entity.reference(),
    );
    assert_eq!(path.callsites().len(), path.frames().len());
    let callsite = path.callsites()[0]
        .as_ref()
        .expect("outer macro retains its invocation anchor");
    assert_eq!(
        callsite.anchor_key(),
        &SourceAnchorKey::new("src/lib.rs", 10, 20)
    );
    let callsite_anchor = index
        .exact_source_anchor(&exact_scope, callsite.anchor_key())
        .unwrap();
    assert_eq!(callsite.anchor(), &callsite_anchor.id());
    assert_scoped_relation::<MacroExpansionHasCallsite>(callsite.relation(), &exact_scope);
    assert_relation_endpoints(
        &workspace,
        callsite.relation(),
        path.frames()[0].reference(),
        callsite_anchor.reference(),
    );
    assert!(path.callsites()[1].is_none());
}

#[test]
fn direct_effect_has_exact_owner_and_no_macro_path() {
    let registry = artifact_registry();
    let (artifact, owner, effect) =
        effect_artifact(&registry, 618, EffectArtifactShape::Direct, None);
    let exact_scope = scope("workspace.direct-effect-path");
    let workspace = WorkspaceFactView::compose([(
        exact_scope.clone(),
        ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
    )])
    .unwrap();
    let index = WorkspaceProgramIndex::open(&workspace, [verified(&exact_scope, 0)]).unwrap();

    assert_eq!(
        index
            .effect_site_edges_owned_by(&exact_scope, &owner)
            .unwrap()
            .len(),
        1
    );
    assert!(
        index
            .effect_macro_path(&exact_scope, &effect)
            .unwrap()
            .is_none()
    );
}

#[test]
fn direct_unsafe_operation_retains_exact_owner_group_sources_and_no_macro_path() {
    let registry = artifact_registry();
    let (artifact, owner, operation) = unsafe_artifact(&registry, 620, UnsafeArtifactShape::Direct);
    let exact_scope = scope("workspace.direct-unsafe-operation");
    let workspace = WorkspaceFactView::compose([(
        exact_scope.clone(),
        ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
    )])
    .unwrap();
    let index = WorkspaceProgramIndex::open(&workspace, [verified(&exact_scope, 0)]).unwrap();
    let body = index.exact_function(&exact_scope, &owner).unwrap();
    let operation_entity = index
        .exact_unsafe_operation(&exact_scope, &operation)
        .unwrap();

    let ownership = index
        .unsafe_operation_edges_owned_by(&exact_scope, &owner)
        .unwrap();
    assert_eq!(ownership.len(), 1);
    assert_eq!(ownership[0].operation(), operation);
    assert_eq!(ownership[0].operation_id(), &operation_entity.id());
    assert_scoped_relation::<FunctionOwnsUnsafeOperation>(ownership[0].relation(), &exact_scope);
    assert_relation_endpoints(
        &workspace,
        ownership[0].relation(),
        body.reference(),
        operation_entity.reference(),
    );

    let group = index
        .unsafe_operation_group_edge(&exact_scope, &operation)
        .unwrap();
    assert_eq!(
        group.group().data().key(),
        &SafetyEffectGroupKey::new(owner, 0)
    );
    assert_eq!(group.group().id().scope(), &exact_scope);
    assert_scoped_relation::<UnsafeOperationInSafetyEffectGroup>(group.relation(), &exact_scope);
    assert_relation_endpoints(
        &workspace,
        group.relation(),
        operation_entity.reference(),
        group.group().reference(),
    );

    let sources = index
        .unsafe_operation_source_anchors(&exact_scope, &operation)
        .unwrap();
    assert_eq!(sources.len(), 2);
    assert_eq!(
        sources[0].role(),
        UnsafeOperationSourceAnchorRole::Presentation
    );
    assert_eq!(sources[1].role(), UnsafeOperationSourceAnchorRole::Expanded);
    for source in sources {
        let anchor = index
            .exact_source_anchor(&exact_scope, source.anchor_key())
            .unwrap();
        assert_eq!(source.anchor(), &anchor.id());
        assert_scoped_relation::<UnsafeOperationHasSourceAnchor>(source.relation(), &exact_scope);
        assert_relation_endpoints(
            &workspace,
            source.relation(),
            operation_entity.reference(),
            anchor.reference(),
        );
    }
    assert!(
        index
            .unsafe_operation_macro_path(&exact_scope, &operation)
            .unwrap()
            .is_none()
    );
}

#[test]
fn valid_direct_unsafe_operation_preserves_empty_optional_metadata() {
    let registry = artifact_registry();
    let (artifact, owner, operation) =
        unsafe_artifact(&registry, 625, UnsafeArtifactShape::DirectWithoutSources);
    let exact_scope = scope("workspace.direct-unsafe-empty-metadata");
    let workspace = WorkspaceFactView::compose([(
        exact_scope.clone(),
        ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
    )])
    .unwrap();
    let index = WorkspaceProgramIndex::open(&workspace, [verified(&exact_scope, 0)]).unwrap();

    assert_eq!(
        index
            .unsafe_operation_edges_owned_by(&exact_scope, &owner)
            .unwrap()
            .len(),
        1
    );
    assert!(
        index
            .unsafe_operation_source_anchors(&exact_scope, &operation)
            .unwrap()
            .is_empty()
    );
    assert!(
        index
            .unsafe_operation_macro_path(&exact_scope, &operation)
            .unwrap()
            .is_none()
    );
}

#[test]
fn unsafe_macro_path_retains_depth_order_exact_relations_and_aligned_callsites() {
    let registry = artifact_registry();
    let (artifact, owner, operation) = unsafe_artifact(&registry, 621, UnsafeArtifactShape::Macro);
    let exact_scope = scope("workspace.unsafe-macro-path");
    let workspace = WorkspaceFactView::compose([(
        exact_scope.clone(),
        ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
    )])
    .unwrap();
    let index = WorkspaceProgramIndex::open(&workspace, [verified(&exact_scope, 0)]).unwrap();
    let body = index.exact_function(&exact_scope, &owner).unwrap();
    let operation_entity = index
        .exact_unsafe_operation(&exact_scope, &operation)
        .unwrap();

    let path = index
        .unsafe_operation_macro_path(&exact_scope, &operation)
        .unwrap()
        .expect("macro-expanded unsafe operation has an exact path");
    assert_eq!(
        path.frames()
            .iter()
            .map(|frame| frame.data().key().depth())
            .collect::<Vec<_>>(),
        [0, 1]
    );
    for frame in path.frames() {
        assert_eq!(
            frame.id(),
            index
                .exact_unsafe_macro(&exact_scope, frame.data().key())
                .unwrap()
                .id()
        );
    }
    assert_scoped_relation::<FunctionEntersUnsafeOperationMacroExpansion>(
        path.entry(),
        &exact_scope,
    );
    assert_relation_endpoints(
        &workspace,
        path.entry(),
        body.reference(),
        path.frames()[0].reference(),
    );
    assert_eq!(path.links().len(), 1);
    assert_scoped_relation::<UnsafeOperationMacroExpansionEntersUnsafeOperationMacroExpansion>(
        &path.links()[0],
        &exact_scope,
    );
    assert_relation_endpoints(
        &workspace,
        &path.links()[0],
        path.frames()[0].reference(),
        path.frames()[1].reference(),
    );
    assert_scoped_relation::<UnsafeOperationMacroExpansionProducesUnsafeOperation>(
        path.exit(),
        &exact_scope,
    );
    assert_relation_endpoints(
        &workspace,
        path.exit(),
        path.frames()[1].reference(),
        operation_entity.reference(),
    );
    assert_eq!(path.callsites().len(), path.frames().len());
    let callsite = path.callsites()[0]
        .as_ref()
        .expect("outer unsafe macro retains its invocation anchor");
    assert_eq!(
        callsite.anchor_key(),
        &SourceAnchorKey::new("src/lib.rs", 10, 20)
    );
    let callsite_anchor = index
        .exact_source_anchor(&exact_scope, callsite.anchor_key())
        .unwrap();
    assert_eq!(callsite.anchor(), &callsite_anchor.id());
    assert_scoped_relation::<UnsafeOperationMacroExpansionHasCallsite>(
        callsite.relation(),
        &exact_scope,
    );
    assert_relation_endpoints(
        &workspace,
        callsite.relation(),
        path.frames()[0].reference(),
        callsite_anchor.reference(),
    );
    assert!(path.callsites()[1].is_none());
}

#[test]
fn exact_unsafe_queries_reject_foreign_and_fabricated_semantic_endpoints() {
    let registry = artifact_registry();
    let (same_artifact_a, same_owner, same_operation) =
        unsafe_artifact(&registry, 622, UnsafeArtifactShape::Direct);
    let (same_artifact_b, _, _) = unsafe_artifact(&registry, 622, UnsafeArtifactShape::Direct);
    let (foreign_artifact, foreign_owner, foreign_operation) =
        unsafe_artifact(&registry, 623, UnsafeArtifactShape::Direct);
    let scope_a = scope("workspace.unsafe-query-a");
    let scope_b = scope("workspace.unsafe-query-b");
    let foreign_scope = scope("workspace.unsafe-query-foreign");
    let workspace = WorkspaceFactView::compose([
        (
            scope_a.clone(),
            ArtifactDbView::open(&same_artifact_a, registry.schemas()).unwrap(),
        ),
        (
            scope_b.clone(),
            ArtifactDbView::open(&same_artifact_b, registry.schemas()).unwrap(),
        ),
        (
            foreign_scope.clone(),
            ArtifactDbView::open(&foreign_artifact, registry.schemas()).unwrap(),
        ),
    ])
    .unwrap();
    let index = WorkspaceProgramIndex::open(
        &workspace,
        [
            verified(&scope_a, 0),
            verified(&scope_b, 0),
            verified(&foreign_scope, 0),
        ],
    )
    .unwrap();

    // Equal semantic keys remain scoped: the selected artifact owns the returned exact refs.
    for exact_scope in [&scope_a, &scope_b] {
        let edges = index
            .unsafe_operation_edges_owned_by(exact_scope, &same_owner)
            .unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].operation(), same_operation);
        assert_eq!(edges[0].operation_id().scope(), exact_scope);
        assert_eq!(edges[0].relation().scope(), exact_scope);
    }

    let fabricated_owner = function(624, None);
    for absent_owner in [foreign_owner, fabricated_owner] {
        assert!(matches!(
            index.unsafe_operation_edges_owned_by(&scope_a, &absent_owner),
            Err(WorkspaceProgramIndexError::InvalidQuery { .. })
        ));
    }

    let fabricated_operation = UnsafeOperationKey::new(same_owner, 99);
    for absent_operation in [foreign_operation, fabricated_operation] {
        assert!(matches!(
            index.unsafe_operation_source_anchors(&scope_a, &absent_operation),
            Err(WorkspaceProgramIndexError::InvalidQuery { .. })
        ));
        assert!(matches!(
            index.unsafe_operation_macro_path(&scope_a, &absent_operation),
            Err(WorkspaceProgramIndexError::InvalidQuery { .. })
        ));
        assert!(matches!(
            index.unsafe_operation_group_edge(&scope_a, &absent_operation),
            Err(WorkspaceProgramIndexError::InvalidQuery { .. })
        ));
    }
}

#[test]
fn malformed_unsafe_ownership_group_sources_and_macro_paths_are_rejected() {
    let registry = artifact_registry();
    let cases = [
        (
            UnsafeArtifactShape::Direct,
            UnsafeArtifactFault::MissingOwner,
        ),
        (
            UnsafeArtifactShape::Direct,
            UnsafeArtifactFault::DuplicateOwner,
        ),
        (UnsafeArtifactShape::Direct, UnsafeArtifactFault::WrongOwner),
        (
            UnsafeArtifactShape::Direct,
            UnsafeArtifactFault::MissingGroup,
        ),
        (
            UnsafeArtifactShape::Direct,
            UnsafeArtifactFault::DuplicateGroup,
        ),
        (UnsafeArtifactShape::Direct, UnsafeArtifactFault::WrongGroup),
        (
            UnsafeArtifactShape::Direct,
            UnsafeArtifactFault::DuplicateSourceRole,
        ),
        (
            UnsafeArtifactShape::Macro,
            UnsafeArtifactFault::NoncontiguousMacroDepth,
        ),
        (
            UnsafeArtifactShape::Macro,
            UnsafeArtifactFault::MissingMacroEntry,
        ),
        (
            UnsafeArtifactShape::Macro,
            UnsafeArtifactFault::DuplicateMacroEntry,
        ),
        (
            UnsafeArtifactShape::Macro,
            UnsafeArtifactFault::SurplusMacroEntry,
        ),
        (
            UnsafeArtifactShape::Macro,
            UnsafeArtifactFault::MissingMacroLink,
        ),
        (
            UnsafeArtifactShape::Macro,
            UnsafeArtifactFault::DuplicateMacroLink,
        ),
        (
            UnsafeArtifactShape::Macro,
            UnsafeArtifactFault::ReversedMacroLink,
        ),
        (
            UnsafeArtifactShape::Macro,
            UnsafeArtifactFault::MissingMacroExit,
        ),
        (
            UnsafeArtifactShape::Macro,
            UnsafeArtifactFault::DuplicateMacroExit,
        ),
        (
            UnsafeArtifactShape::Macro,
            UnsafeArtifactFault::DuplicateMacroCallsite,
        ),
    ];

    for (ordinal, (shape, fault)) in cases.into_iter().enumerate() {
        let (artifact, _, _) =
            unsafe_artifact_with_fault(&registry, 800 + ordinal as u128, shape, Some(fault));
        let exact_scope = scope(&format!("workspace.bad-unsafe-{ordinal}"));
        let workspace = WorkspaceFactView::compose([(
            exact_scope.clone(),
            ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
        )])
        .unwrap();
        assert!(
            matches!(
                WorkspaceProgramIndex::open(&workspace, [verified(&exact_scope, 0)]),
                Err(WorkspaceProgramIndexError::MalformedTopology { .. })
            ),
            "hostile unsafe topology {fault:?} was accepted"
        );
    }
}

#[test]
fn malformed_effect_ownership_sources_and_macro_paths_are_rejected() {
    let registry = artifact_registry();
    let cases = [
        (
            EffectArtifactShape::Direct,
            EffectArtifactFault::MissingOwner,
        ),
        (
            EffectArtifactShape::Direct,
            EffectArtifactFault::DuplicateOwner,
        ),
        (
            EffectArtifactShape::Direct,
            EffectArtifactFault::DuplicateSourceRole,
        ),
        (
            EffectArtifactShape::Macro,
            EffectArtifactFault::NoncontiguousMacroDepth,
        ),
        (
            EffectArtifactShape::Macro,
            EffectArtifactFault::MissingMacroEntry,
        ),
        (
            EffectArtifactShape::Macro,
            EffectArtifactFault::SurplusMacroEntry,
        ),
        (
            EffectArtifactShape::Macro,
            EffectArtifactFault::ReversedMacroLink,
        ),
        (
            EffectArtifactShape::Macro,
            EffectArtifactFault::MissingMacroExit,
        ),
        (
            EffectArtifactShape::Macro,
            EffectArtifactFault::DuplicateMacroExit,
        ),
        (
            EffectArtifactShape::Macro,
            EffectArtifactFault::DuplicateMacroCallsite,
        ),
    ];

    for (ordinal, (shape, fault)) in cases.into_iter().enumerate() {
        let (artifact, _, _) =
            effect_artifact(&registry, 700 + ordinal as u128, shape, Some(fault));
        let exact_scope = scope(&format!("workspace.bad-effect-{ordinal}"));
        let workspace = WorkspaceFactView::compose([(
            exact_scope.clone(),
            ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
        )])
        .unwrap();
        assert!(
            matches!(
                WorkspaceProgramIndex::open(&workspace, [verified(&exact_scope, 0)]),
                Err(WorkspaceProgramIndexError::MalformedTopology { .. })
            ),
            "hostile effect topology {fault:?} was accepted"
        );
    }
}

#[test]
fn marker_claim_candidates_must_share_the_endpoint_macro_path_prefix() {
    let registry = artifact_registry();
    let (artifact, _) = configured_call_artifact(
        &registry,
        620,
        ConfiguredCall {
            kind: CallKind::IndirectCall,
            callable_key: None,
            runtime_target: None,
            opaque_description: Some(String::from("opaque invocation")),
            malformed_macro_depth: None,
            duplicate_presentation_anchors: false,
            marker_candidate_path_mismatch: Some(true),
            duplicate_call_macro_relations: false,
            duplicate_call_macro_callsites: false,
        },
    );
    let exact_scope = scope("workspace.bad-marker-candidate-path");
    let workspace = WorkspaceFactView::compose([(
        exact_scope.clone(),
        ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
    )])
    .unwrap();

    assert!(matches!(
        WorkspaceProgramIndex::open(&workspace, [verified(&exact_scope, 0)]),
        Err(WorkspaceProgramIndexError::MalformedTopology { .. })
    ));
}

#[test]
fn duplicate_call_macro_callsites_are_rejected() {
    let registry = artifact_registry();
    let (artifact, _) = configured_call_artifact(
        &registry,
        625,
        ConfiguredCall {
            kind: CallKind::IndirectCall,
            callable_key: None,
            runtime_target: None,
            opaque_description: Some(String::from("opaque invocation")),
            malformed_macro_depth: None,
            duplicate_presentation_anchors: false,
            marker_candidate_path_mismatch: Some(false),
            duplicate_call_macro_relations: false,
            duplicate_call_macro_callsites: true,
        },
    );
    let exact_scope = scope("workspace.duplicate-call-macro-callsite");
    let workspace = WorkspaceFactView::compose([(
        exact_scope.clone(),
        ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
    )])
    .unwrap();

    assert!(matches!(
        WorkspaceProgramIndex::open(&workspace, [verified(&exact_scope, 0)]),
        Err(WorkspaceProgramIndexError::MalformedTopology { .. })
    ));
}

#[test]
fn call_macro_path_retains_exact_frames_relations_and_callsites() {
    let registry = artifact_registry();
    let (artifact, occurrence) = configured_call_artifact(
        &registry,
        629,
        ConfiguredCall {
            kind: CallKind::IndirectCall,
            callable_key: None,
            runtime_target: None,
            opaque_description: Some(String::from("opaque invocation")),
            malformed_macro_depth: None,
            duplicate_presentation_anchors: false,
            marker_candidate_path_mismatch: Some(false),
            duplicate_call_macro_relations: false,
            duplicate_call_macro_callsites: false,
        },
    );
    let exact_scope = scope("workspace.call-macro-path");
    let workspace = WorkspaceFactView::compose([(
        exact_scope.clone(),
        ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
    )])
    .unwrap();
    let index = WorkspaceProgramIndex::open(&workspace, [verified(&exact_scope, 0)]).unwrap();
    let body = index
        .exact_function(&exact_scope, occurrence.owner())
        .unwrap();
    let occurrence_entity = index
        .exact_call_occurrence(&exact_scope, &occurrence)
        .unwrap();

    let path = index
        .call_macro_path(&exact_scope, &occurrence)
        .unwrap()
        .expect("macro-expanded call retains its exact structural path");
    assert_eq!(path.frames().len(), 2);
    for (depth, frame) in (0_u32..).zip(path.frames()) {
        assert_eq!(frame.data().key().depth(), depth);
        assert_eq!(
            frame.id(),
            index
                .exact_call_macro(&exact_scope, frame.data().key())
                .unwrap()
                .id()
        );
    }
    assert_scoped_relation::<FunctionEntersCallMacroExpansion>(path.entry(), &exact_scope);
    assert_relation_endpoints(
        &workspace,
        path.entry(),
        body.reference(),
        path.frames()[0].reference(),
    );
    assert_eq!(path.links().len(), 1);
    assert_scoped_relation::<CallMacroExpansionEntersCallMacroExpansion>(
        &path.links()[0],
        &exact_scope,
    );
    assert_relation_endpoints(
        &workspace,
        &path.links()[0],
        path.frames()[0].reference(),
        path.frames()[1].reference(),
    );
    assert_scoped_relation::<CallMacroExpansionProducesCallOccurrence>(path.exit(), &exact_scope);
    assert_relation_endpoints(
        &workspace,
        path.exit(),
        path.frames()[1].reference(),
        occurrence_entity.reference(),
    );
    assert_eq!(path.callsites().len(), path.frames().len());
    let callsite = path.callsites()[0]
        .as_ref()
        .expect("outer call macro retains its invocation anchor");
    assert_eq!(
        callsite.anchor_key(),
        &SourceAnchorKey::new("src/lib.rs", 0, 10)
    );
    let callsite_anchor = index
        .exact_source_anchor(&exact_scope, callsite.anchor_key())
        .unwrap();
    assert_eq!(callsite.anchor(), &callsite_anchor.id());
    assert_scoped_relation::<CallMacroExpansionHasCallsite>(callsite.relation(), &exact_scope);
    assert_relation_endpoints(
        &workspace,
        callsite.relation(),
        path.frames()[0].reference(),
        callsite_anchor.reference(),
    );
    assert!(path.callsites()[1].is_none());
}

#[test]
fn validated_marker_candidates_are_retained_as_policy_neutral_inputs() {
    let registry = artifact_registry();
    let (artifact, occurrence) = configured_call_artifact(
        &registry,
        630,
        ConfiguredCall {
            kind: CallKind::IndirectCall,
            callable_key: None,
            runtime_target: None,
            opaque_description: Some(String::from("opaque invocation")),
            malformed_macro_depth: None,
            duplicate_presentation_anchors: false,
            marker_candidate_path_mismatch: Some(false),
            duplicate_call_macro_relations: false,
            duplicate_call_macro_callsites: false,
        },
    );
    let exact_scope = scope("workspace.valid-marker-candidate");
    let workspace = WorkspaceFactView::compose([(
        exact_scope.clone(),
        ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
    )])
    .unwrap();
    let index = WorkspaceProgramIndex::open(&workspace, [verified(&exact_scope, 0)]).unwrap();

    let candidates = index
        .call_marker_candidates(&exact_scope, &occurrence)
        .unwrap();
    let occurrence_entity = index
        .exact_call_occurrence(&exact_scope, &occurrence)
        .unwrap();
    assert_eq!(candidates.len(), 1);
    assert!(candidates[0].source_callsite());
    assert!(!candidates[0].macro_definition_first());
    assert_eq!(candidates[0].claim().source_ordinal(), 0);
    let claim = index
        .exact_marker_claim(&exact_scope, candidates[0].claim())
        .unwrap();
    assert_eq!(candidates[0].claim_id(), &claim.id());
    assert_scoped_relation::<CallOccurrenceHasMarkerClaimCandidate>(
        candidates[0].relation(),
        &exact_scope,
    );
    assert_relation_endpoints(
        &workspace,
        candidates[0].relation(),
        occurrence_entity.reference(),
        claim.reference(),
    );
}

#[test]
fn verified_scope_owners_enforce_permanent_function_provenance_rules() {
    let registry = artifact_registry();
    let exact_external = FunctionKey::new(definition_in_crate(7, 1), Some(instance(700)));
    let valid_consumer = program_artifact(
        &registry,
        &[(
            exact_external,
            FunctionBodyProvenance::ConsumerInstantiation {
                consumer_stable_crate_id: 8,
            },
        )],
    );
    let valid_scope = scope("workspace.valid-provenance");
    let valid_workspace = WorkspaceFactView::compose([(
        valid_scope.clone(),
        ArtifactDbView::open(&valid_consumer, registry.schemas()).unwrap(),
    )])
    .unwrap();
    let valid_index = WorkspaceProgramIndex::open(
        &valid_workspace,
        [VerifiedArtifactOwner::new(valid_scope.clone(), 8)],
    )
    .unwrap();
    assert_eq!(valid_index.stable_crate_id(&valid_scope).unwrap(), 8);

    let invalid = [
        (
            "workspace.bad-defining-owner",
            FunctionKey::new(definition_in_crate(7, 2), None),
            FunctionBodyProvenance::DefiningArtifact,
            8,
        ),
        (
            "workspace.bad-consumer-owner",
            exact_external,
            FunctionBodyProvenance::ConsumerInstantiation {
                consumer_stable_crate_id: 9,
            },
            8,
        ),
        (
            "workspace.bad-local-consumer",
            exact_external,
            FunctionBodyProvenance::ConsumerInstantiation {
                consumer_stable_crate_id: 7,
            },
            7,
        ),
        (
            "workspace.bad-generic-consumer",
            FunctionKey::new(definition_in_crate(7, 3), None),
            FunctionBodyProvenance::ConsumerInstantiation {
                consumer_stable_crate_id: 8,
            },
            8,
        ),
    ];
    for (scope_id, function, provenance, stable_crate_id) in invalid {
        let artifact = program_artifact(&registry, &[(function, provenance)]);
        let exact_scope = scope(scope_id);
        let workspace = WorkspaceFactView::compose([(
            exact_scope.clone(),
            ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
        )])
        .unwrap();
        assert!(matches!(
            WorkspaceProgramIndex::open(
                &workspace,
                [VerifiedArtifactOwner::new(exact_scope, stable_crate_id)],
            ),
            Err(WorkspaceProgramIndexError::MalformedTopology { .. })
        ));
    }
}

#[test]
fn verified_scope_owner_input_must_exactly_cover_the_workspace() {
    let registry = artifact_registry();
    let artifact = program_artifact(
        &registry,
        &[(
            FunctionKey::new(definition_in_crate(7, 1), None),
            FunctionBodyProvenance::DefiningArtifact,
        )],
    );
    let exact_scope = scope("workspace.owner-coverage");
    let workspace = WorkspaceFactView::compose([(
        exact_scope.clone(),
        ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
    )])
    .unwrap();
    let unexpected = scope("workspace.unexpected-owner");

    for owners in [
        Vec::new(),
        vec![VerifiedArtifactOwner::new(unexpected, 7)],
        vec![
            VerifiedArtifactOwner::new(exact_scope.clone(), 7),
            VerifiedArtifactOwner::new(exact_scope.clone(), 7),
        ],
    ] {
        assert!(matches!(
            WorkspaceProgramIndex::open(&workspace, owners),
            Err(WorkspaceProgramIndexError::InvalidScopeOwners { .. })
        ));
    }
}

#[test]
fn function_declaration_anchors_are_optional_unique_and_indexed() {
    let registry = artifact_registry();
    for (suffix, relations, expected_anchor) in [
        ("none", Vec::new(), None),
        (
            "one",
            vec![0],
            Some(SourceAnchorKey::new("src/lib.rs", 0, 10)),
        ),
    ] {
        let (artifact, function, _) = function_anchor_artifact(&registry, &relations);
        let exact_scope = scope(&format!("workspace.function-anchor-{suffix}"));
        let workspace = WorkspaceFactView::compose([(
            exact_scope.clone(),
            ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
        )])
        .unwrap();
        let index = WorkspaceProgramIndex::open(&workspace, [verified(&exact_scope, 0)]).unwrap();
        assert_eq!(
            index
                .function_declaration_anchor(&exact_scope, &function)
                .unwrap()
                .map(|anchor| anchor.data().anchor().clone()),
            expected_anchor
        );
    }

    for (suffix, relations) in [("duplicate", vec![0, 0]), ("multiple", vec![0, 1])] {
        let (artifact, _, _) = function_anchor_artifact(&registry, &relations);
        let exact_scope = scope(&format!("workspace.function-anchor-{suffix}"));
        let workspace = WorkspaceFactView::compose([(
            exact_scope.clone(),
            ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
        )])
        .unwrap();
        assert!(matches!(
            WorkspaceProgramIndex::open(&workspace, [verified(&exact_scope, 0)]),
            Err(WorkspaceProgramIndexError::MalformedTopology { .. })
        ));
    }

    let (mut missing_table, _, _) = function_anchor_artifact(&registry, &[]);
    missing_table
        .tables
        .retain(|table| table.schema.as_str() != FunctionHasSourceAnchor::ID);
    let exact_scope = scope("workspace.function-anchor-missing-table");
    let workspace = WorkspaceFactView::compose([(
        exact_scope.clone(),
        ArtifactDbView::open(&missing_table, registry.schemas()).unwrap(),
    )])
    .unwrap();
    assert!(matches!(
        WorkspaceProgramIndex::open(&workspace, [verified(&exact_scope, 0)]),
        Err(WorkspaceProgramIndexError::InvalidWorkspace { .. })
    ));
}

#[test]
fn source_marker_occurrences_reject_nonempty_macro_paths() {
    let registry = artifact_registry();
    let artifact = malformed_marker_artifact(&registry);
    let exact_scope = scope("workspace.bad-marker-path");
    let workspace = WorkspaceFactView::compose([(
        exact_scope.clone(),
        ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
    )])
    .unwrap();

    assert!(matches!(
        WorkspaceProgramIndex::open(&workspace, [verified(&exact_scope, 0)]),
        Err(WorkspaceProgramIndexError::MalformedTopology { .. })
    ));
}

#[test]
fn unsafe_operations_require_exact_owner_and_group_relations() {
    let registry = artifact_registry();
    let artifact = malformed_unsafe_artifact(&registry);
    let exact_scope = scope("workspace.bad-unsafe-ownership");
    let workspace = WorkspaceFactView::compose([(
        exact_scope.clone(),
        ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
    )])
    .unwrap();

    assert!(matches!(
        WorkspaceProgramIndex::open(&workspace, [verified(&exact_scope, 0)]),
        Err(WorkspaceProgramIndexError::MalformedTopology { .. })
    ));
}
