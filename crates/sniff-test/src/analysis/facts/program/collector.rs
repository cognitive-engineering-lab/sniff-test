//! Sole artifact pass for shared program, source, call, and effect topology.

use std::collections::BTreeMap;

use super::topology::{
    CallMacroExpansionEntersCallMacroExpansion, CallMacroExpansionEntity,
    CallMacroExpansionHasCallsite, CallMacroExpansionKey, CallMacroExpansionProducesCallOccurrence,
    CallOccurrenceEntity, CallOccurrenceHasCallableKey, CallOccurrenceHasSourceAnchor,
    CallOccurrenceInSafetyEffectGroup, CallOccurrenceKey, CallOccurrenceTargetsCallable,
    CallSiteEntity, CallSiteHasOccurrence, CallSiteKey, CallableEntity, CallableKey,
    CallableKeyEntity, FunctionDefinesCallable, FunctionEntersCallMacroExpansion,
    FunctionOwnsCallSite, FunctionOwnsSafetyEffectGroup, SafetyEffectGroupEntity,
    SafetyEffectGroupKey,
};
use super::{
    CoreProgramPack, EffectSiteEntity, EffectSiteHasSourceAnchor, EffectSiteKey,
    FunctionEntersMacroExpansion, FunctionEntity, FunctionHasSourceAnchor, FunctionKey,
    FunctionOwnsEffectSite, MacroExpansionEntersMacroExpansion, MacroExpansionEntity,
    MacroExpansionHasCallsite, MacroExpansionKey, MacroExpansionProducesEffectSite,
    SourceAnchorEntity, SourceAnchorInFile, SourceAnchorKey, SourceFileEntity,
};
use crate::analysis::collected::{
    CollectedArtifact, CollectedCallOccurrence, CollectedEffectSite, CollectedFunctionBody,
    CollectedProgram,
};
use crate::analysis::facts::pack::{AnalysisPack, AnalysisRegistry, PackRegistrationError};
use crate::analysis::facts::pass::{
    ArtifactPass, PassDescriptor, PassError, PassInput, PassOutput,
};
use crate::analysis::facts::schema::{EntityHandle, PassId, RowSchema, SchemaId};

const COLLECT_CORE_PROGRAM_PASS: &str = "sniff-test.core.collect-program";

/// Standalone composition pack for the single authoritative core-program pass.
pub(crate) struct CoreProgramCollectionPack;

impl AnalysisPack<CollectedArtifact> for CoreProgramCollectionPack {
    fn register(
        &self,
        registry: &mut AnalysisRegistry<CollectedArtifact>,
    ) -> Result<(), PackRegistrationError> {
        CoreProgramPack.register(registry)?;
        registry.register_artifact_pass(CollectCoreProgram)
    }
}

struct CollectCoreProgram;

impl ArtifactPass<CollectedArtifact> for CollectCoreProgram {
    fn descriptor(&self) -> PassDescriptor {
        PassDescriptor::new(PassId::new(COLLECT_CORE_PROGRAM_PASS).unwrap())
            .with_writes(core_schema_ids())
    }

    fn run(
        &mut self,
        cx: &CollectedArtifact,
        _input: PassInput<'_>,
        output: &mut PassOutput<'_>,
    ) -> Result<(), PassError> {
        let program = cx.program();
        let handles = CoreHandles::insert(program, output)?;
        emit_relations(program, &handles, output)
    }
}

fn schema<S: RowSchema>() -> SchemaId {
    SchemaId::new(S::ID).expect("built-in core schema IDs are valid")
}

fn core_schema_ids() -> Vec<SchemaId> {
    vec![
        schema::<SourceFileEntity>(),
        schema::<SourceAnchorEntity>(),
        schema::<FunctionEntity>(),
        schema::<EffectSiteEntity>(),
        schema::<MacroExpansionEntity>(),
        schema::<SourceAnchorInFile>(),
        schema::<FunctionOwnsEffectSite>(),
        schema::<FunctionHasSourceAnchor>(),
        schema::<EffectSiteHasSourceAnchor>(),
        schema::<FunctionEntersMacroExpansion>(),
        schema::<MacroExpansionEntersMacroExpansion>(),
        schema::<MacroExpansionProducesEffectSite>(),
        schema::<MacroExpansionHasCallsite>(),
        schema::<CallableEntity>(),
        schema::<CallSiteEntity>(),
        schema::<CallOccurrenceEntity>(),
        schema::<CallableKeyEntity>(),
        schema::<SafetyEffectGroupEntity>(),
        schema::<CallMacroExpansionEntity>(),
        schema::<FunctionDefinesCallable>(),
        schema::<FunctionOwnsCallSite>(),
        schema::<CallSiteHasOccurrence>(),
        schema::<CallOccurrenceTargetsCallable>(),
        schema::<CallOccurrenceHasCallableKey>(),
        schema::<FunctionOwnsSafetyEffectGroup>(),
        schema::<CallOccurrenceInSafetyEffectGroup>(),
        schema::<CallOccurrenceHasSourceAnchor>(),
        schema::<FunctionEntersCallMacroExpansion>(),
        schema::<CallMacroExpansionEntersCallMacroExpansion>(),
        schema::<CallMacroExpansionProducesCallOccurrence>(),
        schema::<CallMacroExpansionHasCallsite>(),
    ]
}

struct CoreHandles {
    source_files: BTreeMap<String, EntityHandle<SourceFileEntity>>,
    source_anchors: BTreeMap<SourceAnchorKey, EntityHandle<SourceAnchorEntity>>,
    callables: BTreeMap<FunctionKey, EntityHandle<CallableEntity>>,
    callable_keys: BTreeMap<CallableKey, EntityHandle<CallableKeyEntity>>,
    functions: BTreeMap<FunctionKey, EntityHandle<FunctionEntity>>,
    call_sites: BTreeMap<CallSiteKey, EntityHandle<CallSiteEntity>>,
    occurrences: BTreeMap<CallOccurrenceKey, EntityHandle<CallOccurrenceEntity>>,
    safety_groups: BTreeMap<SafetyEffectGroupKey, EntityHandle<SafetyEffectGroupEntity>>,
    call_macros: BTreeMap<CallMacroExpansionKey, EntityHandle<CallMacroExpansionEntity>>,
    effects: BTreeMap<EffectSiteKey, EntityHandle<EffectSiteEntity>>,
    effect_macros: BTreeMap<MacroExpansionKey, EntityHandle<MacroExpansionEntity>>,
}

impl CoreHandles {
    fn insert(program: &CollectedProgram, output: &mut PassOutput<'_>) -> Result<Self, PassError> {
        let mut handles = Self {
            source_files: BTreeMap::new(),
            source_anchors: BTreeMap::new(),
            callables: BTreeMap::new(),
            callable_keys: BTreeMap::new(),
            functions: BTreeMap::new(),
            call_sites: BTreeMap::new(),
            occurrences: BTreeMap::new(),
            safety_groups: BTreeMap::new(),
            call_macros: BTreeMap::new(),
            effects: BTreeMap::new(),
            effect_macros: BTreeMap::new(),
        };

        for entity in program.source_files() {
            handles
                .source_files
                .insert(entity.id().to_owned(), output.insert_entity(entity)?);
        }
        for entity in program.source_anchors() {
            handles
                .source_anchors
                .insert(entity.anchor().clone(), output.insert_entity(entity)?);
        }
        for entity in program.callables() {
            handles
                .callables
                .insert(*entity.key(), output.insert_entity(entity)?);
        }
        for entity in program.callable_keys() {
            handles
                .callable_keys
                .insert(*entity.key(), output.insert_entity(entity)?);
        }
        for body in program.bodies() {
            handles
                .functions
                .insert(*body.entity().key(), output.insert_entity(body.entity())?);
            handles.insert_body_entities(body, output)?;
        }
        Ok(handles)
    }

    fn insert_body_entities(
        &mut self,
        body: &CollectedFunctionBody,
        output: &mut PassOutput<'_>,
    ) -> Result<(), PassError> {
        for group in body.safety_effect_groups() {
            self.safety_groups
                .insert(*group.key(), output.insert_entity(group)?);
        }
        for site in body.call_sites() {
            self.call_sites
                .insert(*site.entity().key(), output.insert_entity(site.entity())?);
            for occurrence in site.occurrences() {
                self.occurrences.insert(
                    *occurrence.entity().key(),
                    output.insert_entity(occurrence.entity())?,
                );
                for frame in occurrence.macro_frames() {
                    self.call_macros
                        .insert(*frame.entity().key(), output.insert_entity(frame.entity())?);
                }
            }
        }
        for effect in body.effect_sites() {
            self.effects.insert(
                *effect.entity().site(),
                output.insert_entity(effect.entity())?,
            );
            for frame in effect.macro_frames() {
                self.effect_macros.insert(
                    frame.entity().expansion().clone(),
                    output.insert_entity(frame.entity())?,
                );
            }
        }
        Ok(())
    }
}

fn emit_relations(
    program: &CollectedProgram,
    handles: &CoreHandles,
    output: &mut PassOutput<'_>,
) -> Result<(), PassError> {
    for anchor in program.source_anchors() {
        output.relate(
            source_anchor_handle(handles, anchor.anchor()),
            handles
                .source_files
                .get(anchor.anchor().file())
                .expect("validated source anchor has a source file"),
            &SourceAnchorInFile::new(),
        )?;
    }
    for body in program.bodies() {
        emit_body_relations(body, handles, output)?;
    }
    Ok(())
}

fn emit_body_relations(
    body: &CollectedFunctionBody,
    handles: &CoreHandles,
    output: &mut PassOutput<'_>,
) -> Result<(), PassError> {
    let function = handles
        .functions
        .get(body.entity().key())
        .expect("validated body has a function entity");
    output.relate(
        function,
        handles
            .callables
            .get(body.entity().key())
            .expect("validated body has callable metadata"),
        &FunctionDefinesCallable::new(),
    )?;
    if let Some(anchor) = body.source_anchor() {
        output.relate(
            function,
            source_anchor_handle(handles, anchor),
            &FunctionHasSourceAnchor::new(),
        )?;
    }
    for group in body.safety_effect_groups() {
        output.relate(
            function,
            handles
                .safety_groups
                .get(group.key())
                .expect("validated body has its safety group"),
            &FunctionOwnsSafetyEffectGroup::new(),
        )?;
    }
    for site in body.call_sites() {
        let site_handle = handles
            .call_sites
            .get(site.entity().key())
            .expect("validated body has its call site");
        output.relate(function, site_handle, &FunctionOwnsCallSite::new())?;
        for occurrence in site.occurrences() {
            emit_occurrence_relations(occurrence, function, site_handle, handles, output)?;
        }
    }
    for effect in body.effect_sites() {
        emit_effect_relations(effect, function, handles, output)?;
    }
    Ok(())
}

fn emit_occurrence_relations(
    occurrence: &CollectedCallOccurrence,
    function: &EntityHandle<FunctionEntity>,
    site: &EntityHandle<CallSiteEntity>,
    handles: &CoreHandles,
    output: &mut PassOutput<'_>,
) -> Result<(), PassError> {
    let occurrence_handle = handles
        .occurrences
        .get(occurrence.entity().key())
        .expect("validated call site has its occurrence");
    output.relate(site, occurrence_handle, &CallSiteHasOccurrence::new())?;
    for target in occurrence.targets() {
        output.relate(
            occurrence_handle,
            handles
                .callables
                .get(target.callable())
                .expect("validated occurrence target has callable metadata"),
            &CallOccurrenceTargetsCallable::new(target.role()),
        )?;
    }
    for key in occurrence.callable_keys() {
        output.relate(
            occurrence_handle,
            handles
                .callable_keys
                .get(key)
                .expect("validated occurrence key has a callable-key entity"),
            &CallOccurrenceHasCallableKey::new(),
        )?;
    }
    output.relate(
        occurrence_handle,
        handles
            .safety_groups
            .get(occurrence.safety_effect_group())
            .expect("validated occurrence has an owned safety group"),
        &CallOccurrenceInSafetyEffectGroup::new(),
    )?;
    for anchor in occurrence.source_anchors() {
        output.relate(
            occurrence_handle,
            source_anchor_handle(handles, anchor.anchor()),
            &CallOccurrenceHasSourceAnchor::new(anchor.role()),
        )?;
    }
    emit_call_macro_path(occurrence, function, occurrence_handle, handles, output)
}

fn emit_call_macro_path(
    occurrence: &CollectedCallOccurrence,
    function: &EntityHandle<FunctionEntity>,
    occurrence_handle: &EntityHandle<CallOccurrenceEntity>,
    handles: &CoreHandles,
    output: &mut PassOutput<'_>,
) -> Result<(), PassError> {
    let frames = occurrence
        .macro_frames()
        .iter()
        .map(|frame| {
            handles
                .call_macros
                .get(frame.entity().key())
                .expect("validated occurrence has its macro frame")
        })
        .collect::<Vec<_>>();
    if let Some(first) = frames.first() {
        output.relate(function, *first, &FunctionEntersCallMacroExpansion::new())?;
        for pair in frames.windows(2) {
            output.relate(
                pair[0],
                pair[1],
                &CallMacroExpansionEntersCallMacroExpansion::new(),
            )?;
        }
        output.relate(
            frames.last().expect("nonempty macro path has a last frame"),
            occurrence_handle,
            &CallMacroExpansionProducesCallOccurrence::new(),
        )?;
    }
    for frame in occurrence.macro_frames() {
        if let Some(callsite) = frame.callsite() {
            output.relate(
                handles
                    .call_macros
                    .get(frame.entity().key())
                    .expect("validated occurrence has its macro frame"),
                source_anchor_handle(handles, callsite),
                &CallMacroExpansionHasCallsite::new(),
            )?;
        }
    }
    Ok(())
}

fn emit_effect_relations(
    effect: &CollectedEffectSite,
    function: &EntityHandle<FunctionEntity>,
    handles: &CoreHandles,
    output: &mut PassOutput<'_>,
) -> Result<(), PassError> {
    let effect_handle = handles
        .effects
        .get(effect.entity().site())
        .expect("validated body has its effect site");
    output.relate(function, effect_handle, &FunctionOwnsEffectSite::new())?;
    for anchor in effect.source_anchors() {
        output.relate(
            effect_handle,
            source_anchor_handle(handles, anchor.anchor()),
            &EffectSiteHasSourceAnchor::new(anchor.role()),
        )?;
    }
    emit_effect_macro_path(effect, function, effect_handle, handles, output)
}

fn emit_effect_macro_path(
    effect: &CollectedEffectSite,
    function: &EntityHandle<FunctionEntity>,
    effect_handle: &EntityHandle<EffectSiteEntity>,
    handles: &CoreHandles,
    output: &mut PassOutput<'_>,
) -> Result<(), PassError> {
    let frames = effect
        .macro_frames()
        .iter()
        .map(|frame| {
            handles
                .effect_macros
                .get(frame.entity().expansion())
                .expect("validated effect has its macro frame")
        })
        .collect::<Vec<_>>();
    if let Some(first) = frames.first() {
        output.relate(function, *first, &FunctionEntersMacroExpansion::new())?;
        for pair in frames.windows(2) {
            output.relate(pair[0], pair[1], &MacroExpansionEntersMacroExpansion::new())?;
        }
        output.relate(
            frames.last().expect("nonempty macro path has a last frame"),
            effect_handle,
            &MacroExpansionProducesEffectSite::new(),
        )?;
    }
    for frame in effect.macro_frames() {
        if let Some(callsite) = frame.callsite() {
            output.relate(
                handles
                    .effect_macros
                    .get(frame.entity().expansion())
                    .expect("validated effect has its macro frame"),
                source_anchor_handle(handles, callsite),
                &MacroExpansionHasCallsite::new(),
            )?;
        }
    }
    Ok(())
}

fn source_anchor_handle<'a>(
    handles: &'a CoreHandles,
    anchor: &SourceAnchorKey,
) -> &'a EntityHandle<SourceAnchorEntity> {
    handles
        .source_anchors
        .get(anchor)
        .expect("validated relationship has its source anchor")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use reachability::MirBodyLocation;

    use super::{COLLECT_CORE_PROGRAM_PASS, CoreProgramCollectionPack};
    use crate::analysis::collected::{
        CollectedArtifact, CollectedCallMacroFrame, CollectedCallOccurrence, CollectedCallSite,
        CollectedCallSourceAnchor, CollectedCallTarget, CollectedEffectMacroFrame,
        CollectedEffectSite, CollectedEffectSourceAnchor, CollectedFunctionBody, CollectedProgram,
        CollectedProgramError,
    };
    use crate::analysis::facts::builder::ArtifactDbBuilder;
    use crate::analysis::facts::pack::AnalysisRegistry;
    use crate::analysis::facts::program::topology::{
        CallAttributionRole, CallKind, CallMacroExpansionEntersCallMacroExpansion,
        CallMacroExpansionEntity, CallMacroExpansionHasCallsite, CallMacroExpansionKey,
        CallMacroExpansionProducesCallOccurrence, CallOccurrenceEntity,
        CallOccurrenceHasCallableKey, CallOccurrenceHasSourceAnchor,
        CallOccurrenceInSafetyEffectGroup, CallOccurrenceKey, CallOccurrenceTargetsCallable,
        CallSiteEntity, CallSiteHasOccurrence, CallSiteKey, CallSourceAnchorRole, CallTargetRole,
        CallableEntity, CallableKey, FunctionDefinesCallable, FunctionEntersCallMacroExpansion,
        FunctionOwnsCallSite, FunctionOwnsSafetyEffectGroup, SafetyEffectGroupEntity,
        SafetyEffectGroupKey,
    };
    use crate::analysis::facts::program::{
        EffectSiteEntity, EffectSiteHasSourceAnchor, EffectSiteKey, EffectSourceAnchorRole,
        FunctionBodyProvenance, FunctionEntersMacroExpansion, FunctionEntity,
        FunctionHasSourceAnchor, FunctionKey, FunctionOwnsEffectSite,
        MacroExpansionEntersMacroExpansion, MacroExpansionEntity, MacroExpansionHasCallsite,
        MacroExpansionKey, MacroExpansionProducesEffectSite, SourceAnchorEntity,
        SourceAnchorInFile, SourceAnchorKey, SourceFileEntity,
    };
    use crate::analysis::facts::schema::RowSchema;
    use crate::analysis::facts::view::ArtifactDbView;
    use crate::namespace::{
        StableDefPathHash, StableExpansionHash, StableInstanceHash, StableTypeHash,
    };

    fn definition(value: u128) -> StableDefPathHash {
        serde_json::from_str(&format!("\"{value:032x}\"")).expect("valid definition hash")
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

    fn function(value: u128) -> FunctionKey {
        FunctionKey::new(definition(value), Some(instance(value + 100)))
    }

    fn generic_function(value: u128) -> FunctionKey {
        FunctionKey::new(definition(value), None)
    }

    fn anchor(start: u64, end: u64) -> SourceAnchorKey {
        SourceAnchorKey::new("src/lib.rs", start, end)
    }

    fn callable(key: FunctionKey, path: &str) -> CallableEntity {
        CallableEntity::new(key, path, false, false, true, false, vec![path.to_owned()])
    }

    fn sample_occurrence(
        owner: FunctionKey,
        runtime_target: FunctionKey,
        source_target: FunctionKey,
        reverse: bool,
    ) -> CollectedCallOccurrence {
        let occurrence_key = CallOccurrenceKey::new(owner, 9);
        let mut call_frames = vec![
            CollectedCallMacroFrame::new(
                CallMacroExpansionEntity::new(
                    CallMacroExpansionKey::new(occurrence_key, 0),
                    expansion(1_030),
                    definition(30),
                    "outer!",
                ),
                Some(anchor(30, 35)),
            ),
            CollectedCallMacroFrame::new(
                CallMacroExpansionEntity::new(
                    CallMacroExpansionKey::new(occurrence_key, 1),
                    expansion(1_031),
                    definition(31),
                    "inner!",
                ),
                Some(anchor(40, 45)),
            ),
        ];
        if reverse {
            call_frames.reverse();
        }

        CollectedCallOccurrence::new(
            CallOccurrenceEntity::new(
                occurrence_key,
                CallKind::DirectCall,
                vec![
                    CallAttributionRole::CallSite,
                    CallAttributionRole::ErasureSite,
                ],
                false,
                false,
                None,
            ),
            vec![
                CollectedCallTarget::new(CallTargetRole::Runtime, runtime_target),
                CollectedCallTarget::new(CallTargetRole::SourceContract, source_target),
            ],
            vec![
                CallableKey::FnPointer(type_hash(71)),
                CallableKey::FnPointer(type_hash(70)),
            ],
            vec![SafetyEffectGroupKey::new(owner, 7)],
            vec![
                CollectedCallSourceAnchor::new(CallSourceAnchorRole::Presentation, anchor(10, 15)),
                CollectedCallSourceAnchor::new(CallSourceAnchorRole::Expanded, anchor(20, 25)),
            ],
            call_frames,
        )
    }

    fn sample_effect(owner: FunctionKey, reverse: bool) -> CollectedEffectSite {
        let effect_key = EffectSiteKey::from_mir(
            owner,
            MirBodyLocation {
                basic_block: 3,
                statement_index: 4,
            },
        )
        .unwrap();
        let mut effect_frames = vec![
            CollectedEffectMacroFrame::new(
                MacroExpansionEntity::new(
                    MacroExpansionKey::new(effect_key, 0),
                    expansion(1_040),
                    definition(40),
                    "assert_outer!",
                ),
                Some(anchor(50, 55)),
            ),
            CollectedEffectMacroFrame::new(
                MacroExpansionEntity::new(
                    MacroExpansionKey::new(effect_key, 1),
                    expansion(1_041),
                    definition(41),
                    "assert_inner!",
                ),
                Some(anchor(60, 65)),
            ),
        ];
        if reverse {
            effect_frames.reverse();
        }

        CollectedEffectSite::new(
            EffectSiteEntity::new(effect_key),
            vec![
                CollectedEffectSourceAnchor::new(
                    EffectSourceAnchorRole::Presentation,
                    anchor(70, 75),
                ),
                CollectedEffectSourceAnchor::new(EffectSourceAnchorRole::Expanded, anchor(80, 85)),
            ],
            effect_frames,
        )
    }

    fn sample_program(reverse: bool) -> CollectedProgram {
        let owner = function(1);
        let target = function(2);
        let source_target = generic_function(2);
        let body = CollectedFunctionBody::new(
            FunctionEntity::new(
                owner,
                "local::body",
                FunctionBodyProvenance::DefiningArtifact,
            ),
            Some(anchor(0, 5)),
            vec![CollectedCallSite::new(
                CallSiteEntity::new(CallSiteKey::new(owner, 2)),
                vec![sample_occurrence(owner, target, source_target, reverse)],
            )],
            vec![SafetyEffectGroupEntity::new(SafetyEffectGroupKey::new(
                owner, 7,
            ))],
            vec![sample_effect(owner, reverse)],
        );

        let mut files = vec![SourceFileEntity::new(
            "src/lib.rs",
            "src/lib.rs",
            "verified-content-hash",
            100,
        )];
        let mut anchors = [
            anchor(0, 5),
            anchor(10, 15),
            anchor(20, 25),
            anchor(30, 35),
            anchor(40, 45),
            anchor(50, 55),
            anchor(60, 65),
            anchor(70, 75),
            anchor(80, 85),
        ]
        .into_iter()
        .map(SourceAnchorEntity::new)
        .collect::<Vec<_>>();
        let mut callables = vec![
            callable(owner, "local::body"),
            callable(target, "dep::target"),
            callable(source_target, "dep::target"),
        ];
        let mut bodies = vec![body];
        if reverse {
            files.reverse();
            anchors.reverse();
            callables.reverse();
            bodies.reverse();
        }
        CollectedProgram::try_new(files, anchors, callables, bodies).unwrap()
    }

    fn collect(program: CollectedProgram) -> crate::analysis::facts::encoded::ArtifactFactIr {
        let artifact = CollectedArtifact::new(program);
        let mut registry = AnalysisRegistry::<CollectedArtifact>::new();
        registry.install(&CoreProgramCollectionPack).unwrap();
        let mut builder = ArtifactDbBuilder::new();
        registry
            .run_artifact_passes(&artifact, &mut builder)
            .unwrap();
        builder.finalize(registry.schemas()).unwrap()
    }

    fn registered_core_schema_ids() -> BTreeSet<crate::analysis::facts::schema::SchemaId> {
        let mut registry = AnalysisRegistry::<CollectedArtifact>::new();
        registry.install(&CoreProgramCollectionPack).unwrap();
        registry
            .schemas()
            .descriptors()
            .map(|descriptor| descriptor.id().clone())
            .collect()
    }

    #[test]
    fn collection_pack_registers_exactly_one_complete_core_pass() {
        let mut registry = AnalysisRegistry::<CollectedArtifact>::new();
        registry.install(&CoreProgramCollectionPack).unwrap();

        let descriptors = registry.artifact_passes().descriptors().collect::<Vec<_>>();
        assert_eq!(descriptors.len(), 1);
        assert_eq!(descriptors[0].id.as_str(), COLLECT_CORE_PROGRAM_PASS);
        assert!(descriptors[0].reads.is_empty());
        assert_eq!(
            descriptors[0]
                .writes
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>(),
            registered_core_schema_ids()
        );
    }

    #[test]
    fn empty_collection_materializes_every_declared_core_table() {
        let ir = collect(
            CollectedProgram::try_new(Vec::new(), Vec::new(), Vec::new(), Vec::new()).unwrap(),
        );
        assert_eq!(ir.tables.len(), registered_core_schema_ids().len());
        assert_eq!(
            ir.tables
                .iter()
                .map(|table| table.schema.clone())
                .collect::<BTreeSet<_>>(),
            registered_core_schema_ids()
        );
        assert!(ir.tables.iter().all(|table| table.rows.is_empty()));
        assert!(ir.relation_index.is_empty());
    }

    #[test]
    fn representative_collection_emits_every_core_relation_deterministically() {
        let forward = collect(sample_program(false));
        let reversed = collect(sample_program(true));
        assert_eq!(forward, reversed);

        let mut registry = AnalysisRegistry::<CollectedArtifact>::new();
        registry.install(&CoreProgramCollectionPack).unwrap();
        let view = ArtifactDbView::open(&forward, registry.schemas()).unwrap();
        macro_rules! assert_rows {
            ($schema:ty, $count:expr) => {
                assert_eq!(
                    view.table::<$schema>().unwrap().len(),
                    $count,
                    "{}",
                    <$schema>::ID
                )
            };
        }
        assert_rows!(SourceAnchorInFile, 9);
        assert_rows!(FunctionOwnsEffectSite, 1);
        assert_rows!(FunctionHasSourceAnchor, 1);
        assert_rows!(EffectSiteHasSourceAnchor, 2);
        assert_rows!(FunctionEntersMacroExpansion, 1);
        assert_rows!(MacroExpansionEntersMacroExpansion, 1);
        assert_rows!(MacroExpansionProducesEffectSite, 1);
        assert_rows!(MacroExpansionHasCallsite, 2);
        assert_rows!(FunctionDefinesCallable, 1);
        assert_rows!(FunctionOwnsCallSite, 1);
        assert_rows!(CallSiteHasOccurrence, 1);
        assert_rows!(CallOccurrenceTargetsCallable, 2);
        assert_rows!(CallOccurrenceHasCallableKey, 2);
        assert_rows!(FunctionOwnsSafetyEffectGroup, 1);
        assert_rows!(CallOccurrenceInSafetyEffectGroup, 1);
        assert_rows!(CallOccurrenceHasSourceAnchor, 2);
        assert_rows!(FunctionEntersCallMacroExpansion, 1);
        assert_rows!(CallMacroExpansionEntersCallMacroExpansion, 1);
        assert_rows!(CallMacroExpansionProducesCallOccurrence, 1);
        assert_rows!(CallMacroExpansionHasCallsite, 2);
    }

    #[test]
    fn malformed_model_is_rejected_before_the_pass_can_mutate_a_builder() {
        let mut registry = AnalysisRegistry::<CollectedArtifact>::new();
        registry.install(&CoreProgramCollectionPack).unwrap();
        let mut builder = ArtifactDbBuilder::new();
        builder
            .insert_entity(&SourceFileEntity::new("kept", "kept.rs", "hash", 1))
            .unwrap();
        let before = builder.clone().finalize(registry.schemas()).unwrap();

        let malformed = CollectedProgram::try_new(
            vec![
                SourceFileEntity::new("same", "first.rs", "hash", 1),
                SourceFileEntity::new("same", "second.rs", "hash", 1),
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        assert!(matches!(
            malformed,
            Err(CollectedProgramError::ConflictingSourceFile { source_file })
                if source_file == "same"
        ));
        assert_eq!(builder.finalize(registry.schemas()).unwrap(), before);
    }
}
