//! Sole artifact pass for documented safety contracts and unsafe operations.

use super::operations::{
    FunctionEntersUnsafeOperationMacroExpansion, FunctionOwnsUnsafeOperation,
    UnsafeOperationEntity, UnsafeOperationHasSourceAnchor, UnsafeOperationInSafetyEffectGroup,
    UnsafeOperationMacroExpansionEntersUnsafeOperationMacroExpansion,
    UnsafeOperationMacroExpansionEntity, UnsafeOperationMacroExpansionHasCallsite,
    UnsafeOperationMacroExpansionProducesUnsafeOperation,
};
use super::{SafetyContractFact, SafetyRequirement};
use crate::analysis::collected::{
    CollectedArtifact, CollectedSafetyContract, CollectedUnsafeOperation,
};
use crate::analysis::facts::pack::{AnalysisPack, AnalysisRegistry, PackRegistrationError};
use crate::analysis::facts::pass::{
    ArtifactPass, PassDescriptor, PassError, PassInput, PassOutput,
};
use crate::analysis::facts::program::topology::{CallableEntity, SafetyEffectGroupEntity};
use crate::analysis::facts::program::{FunctionEntity, SourceAnchorEntity, SourceAnchorKey};
use crate::analysis::facts::schema::{EntityHandle, PassId, RowSchema, SchemaId};

pub(crate) const COLLECT_SAFETY_ARTIFACT_PASS: &str = "sniff-test.safety.collect-artifact";

/// Composition pack for the single authoritative safety-domain producer.
pub(crate) struct SafetyCollectionPack;

impl AnalysisPack<CollectedArtifact> for SafetyCollectionPack {
    fn register(
        &self,
        registry: &mut AnalysisRegistry<CollectedArtifact>,
    ) -> Result<(), PackRegistrationError> {
        super::register_artifact_schemas(registry)?;
        registry.register_artifact_pass(CollectSafetyArtifact)
    }
}

struct CollectSafetyArtifact;

impl ArtifactPass<CollectedArtifact> for CollectSafetyArtifact {
    fn descriptor(&self) -> PassDescriptor {
        PassDescriptor::new(PassId::new(COLLECT_SAFETY_ARTIFACT_PASS).unwrap())
            .with_reads([
                schema::<CallableEntity>(),
                schema::<FunctionEntity>(),
                schema::<SafetyEffectGroupEntity>(),
                schema::<SourceAnchorEntity>(),
            ])
            .with_writes(safety_schema_ids())
    }

    fn run(
        &mut self,
        cx: &CollectedArtifact,
        _input: PassInput<'_>,
        output: &mut PassOutput<'_>,
    ) -> Result<(), PassError> {
        for operation in cx.unsafe_operations() {
            emit_operation(operation, output)?;
        }
        for contract in cx.safety_contracts() {
            emit_contract(contract, output)?;
        }
        Ok(())
    }
}

fn schema<S: RowSchema>() -> SchemaId {
    SchemaId::new(S::ID).expect("built-in safety schema IDs are valid")
}

fn safety_schema_ids() -> Vec<SchemaId> {
    vec![
        schema::<SafetyContractFact>(),
        schema::<SafetyRequirement>(),
        schema::<UnsafeOperationEntity>(),
        schema::<UnsafeOperationMacroExpansionEntity>(),
        schema::<FunctionOwnsUnsafeOperation>(),
        schema::<UnsafeOperationInSafetyEffectGroup>(),
        schema::<UnsafeOperationHasSourceAnchor>(),
        schema::<FunctionEntersUnsafeOperationMacroExpansion>(),
        schema::<UnsafeOperationMacroExpansionEntersUnsafeOperationMacroExpansion>(),
        schema::<UnsafeOperationMacroExpansionProducesUnsafeOperation>(),
        schema::<UnsafeOperationMacroExpansionHasCallsite>(),
    ]
}

fn emit_operation(
    operation: &CollectedUnsafeOperation,
    output: &mut PassOutput<'_>,
) -> Result<(), PassError> {
    let operation_handle = output.insert_entity(operation.entity())?;
    let function = EntityHandle::<FunctionEntity>::new(*operation.entity().key().owner());
    let group = EntityHandle::<SafetyEffectGroupEntity>::new(*operation.safety_effect_group());
    output.relate(
        &function,
        &operation_handle,
        &FunctionOwnsUnsafeOperation::new(),
    )?;
    output.relate(
        &operation_handle,
        &group,
        &UnsafeOperationInSafetyEffectGroup::new(),
    )?;
    for anchor in operation.source_anchors() {
        output.relate(
            &operation_handle,
            &source_anchor_handle(anchor.anchor()),
            &UnsafeOperationHasSourceAnchor::new(anchor.role()),
        )?;
    }

    let mut frames = Vec::with_capacity(operation.macro_frames().len());
    for frame in operation.macro_frames() {
        frames.push(output.insert_entity(frame.entity())?);
    }
    if let Some(first) = frames.first() {
        output.relate(
            &function,
            first,
            &FunctionEntersUnsafeOperationMacroExpansion::new(),
        )?;
        for pair in frames.windows(2) {
            output.relate(
                &pair[0],
                &pair[1],
                &UnsafeOperationMacroExpansionEntersUnsafeOperationMacroExpansion::new(),
            )?;
        }
        output.relate(
            frames.last().expect("nonempty macro path has a last frame"),
            &operation_handle,
            &UnsafeOperationMacroExpansionProducesUnsafeOperation::new(),
        )?;
    }
    for (frame, handle) in operation.macro_frames().iter().zip(&frames) {
        if let Some(callsite) = frame.callsite() {
            output.relate(
                handle,
                &source_anchor_handle(callsite),
                &UnsafeOperationMacroExpansionHasCallsite::new(),
            )?;
        }
    }
    Ok(())
}

fn emit_contract(
    contract: &CollectedSafetyContract,
    output: &mut PassOutput<'_>,
) -> Result<(), PassError> {
    let owner = EntityHandle::<CallableEntity>::new(*contract.owner());
    let mut metadata = output.fact_meta();
    metadata = output.with_fact_owner(metadata, &owner)?;
    if let Some(anchor) = contract.source_anchor() {
        metadata = output.with_fact_anchor(metadata, &source_anchor_handle(anchor))?;
    }
    for requirement in contract.requirements() {
        let requirement = output.insert_requirement(requirement)?;
        metadata = output.with_fact_requirement(metadata, &requirement)?;
    }
    output.insert_fact(&SafetyContractFact::new(), metadata)
}

fn source_anchor_handle(anchor: &SourceAnchorKey) -> EntityHandle<SourceAnchorEntity> {
    EntityHandle::new(anchor.clone())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{COLLECT_SAFETY_ARTIFACT_PASS, SafetyCollectionPack};
    use crate::analysis::collected::{
        CollectedArtifact, CollectedArtifactInput, CollectedFunctionBody, CollectedProgram,
        CollectedSafetyContract, CollectedUnsafeOperation, CollectedUnsafeOperationMacroFrame,
        CollectedUnsafeOperationSourceAnchor,
    };
    use crate::analysis::facts::builder::ArtifactDbBuilder;
    use crate::analysis::facts::pack::AnalysisRegistry;
    use crate::analysis::facts::program::collector::CoreProgramCollectionPack;
    use crate::analysis::facts::program::topology::{
        CallableEntity, SafetyEffectGroupEntity, SafetyEffectGroupKey,
    };
    use crate::analysis::facts::program::{
        FunctionBodyProvenance, FunctionEntity, FunctionKey, SourceAnchorEntity, SourceAnchorKey,
        SourceFileEntity,
    };
    use crate::analysis::facts::safety::operations::{
        FunctionEntersUnsafeOperationMacroExpansion, FunctionOwnsUnsafeOperation,
        SafetyOperationKind, UnsafeOperationEntity, UnsafeOperationHasSourceAnchor,
        UnsafeOperationInSafetyEffectGroup, UnsafeOperationKey,
        UnsafeOperationMacroExpansionEntersUnsafeOperationMacroExpansion,
        UnsafeOperationMacroExpansionEntity, UnsafeOperationMacroExpansionHasCallsite,
        UnsafeOperationMacroExpansionKey, UnsafeOperationMacroExpansionProducesUnsafeOperation,
        UnsafeOperationSourceAnchorRole,
    };
    use crate::analysis::facts::safety::{SafetyContractFact, SafetyRequirement};
    use crate::analysis::facts::schema::{RowSchema, SchemaId};
    use crate::analysis::facts::view::ArtifactDbView;
    use crate::namespace::{StableDefPathHash, StableExpansionHash};

    fn definition(value: u128) -> StableDefPathHash {
        serde_json::from_str(&format!("\"{value:032x}\"")).expect("valid definition hash")
    }

    fn expansion(value: u128) -> StableExpansionHash {
        serde_json::from_str(&format!("\"{value:032x}\"")).expect("valid expansion hash")
    }

    fn function(value: u128) -> FunctionKey {
        FunctionKey::new(definition(value), None)
    }

    fn anchor(start: u64, end: u64) -> SourceAnchorKey {
        SourceAnchorKey::new("src/lib.rs", start, end)
    }

    fn operation(
        owner: FunctionKey,
        local_id: u32,
        with_provenance: bool,
    ) -> CollectedUnsafeOperation {
        let key = UnsafeOperationKey::new(owner, local_id);
        let (source_anchors, macro_frames) = if with_provenance {
            (
                vec![
                    CollectedUnsafeOperationSourceAnchor::new(
                        UnsafeOperationSourceAnchorRole::Expanded,
                        anchor(20, 25),
                    ),
                    CollectedUnsafeOperationSourceAnchor::new(
                        UnsafeOperationSourceAnchorRole::Presentation,
                        anchor(10, 15),
                    ),
                ],
                vec![
                    CollectedUnsafeOperationMacroFrame::new(
                        UnsafeOperationMacroExpansionEntity::new(
                            UnsafeOperationMacroExpansionKey::new(key, 1),
                            expansion(1_031),
                            definition(31),
                            "inner!",
                        ),
                        Some(anchor(40, 45)),
                    ),
                    CollectedUnsafeOperationMacroFrame::new(
                        UnsafeOperationMacroExpansionEntity::new(
                            UnsafeOperationMacroExpansionKey::new(key, 0),
                            expansion(1_030),
                            definition(30),
                            "outer!",
                        ),
                        Some(anchor(30, 35)),
                    ),
                ],
            )
        } else {
            (Vec::new(), Vec::new())
        };
        CollectedUnsafeOperation::new(
            UnsafeOperationEntity::new(key, SafetyOperationKind::DerefRawPointer),
            SafetyEffectGroupKey::new(owner, 7),
            source_anchors,
            macro_frames,
        )
    }

    fn artifact(reverse: bool) -> CollectedArtifact {
        let owner = function(1);
        let bodyless = function(2);
        let body = CollectedFunctionBody::new(
            FunctionEntity::new(
                owner,
                "crate::body",
                FunctionBodyProvenance::DefiningArtifact,
            ),
            Some(anchor(0, 5)),
            Vec::new(),
            vec![SafetyEffectGroupEntity::new(SafetyEffectGroupKey::new(
                owner, 7,
            ))],
            Vec::new(),
        );
        let mut files = vec![SourceFileEntity::new(
            "src/lib.rs",
            "src/lib.rs",
            "verified-hash",
            100,
        )];
        let mut anchors = [
            anchor(0, 5),
            anchor(10, 15),
            anchor(20, 25),
            anchor(30, 35),
            anchor(40, 45),
            anchor(50, 55),
        ]
        .into_iter()
        .map(SourceAnchorEntity::new)
        .collect::<Vec<_>>();
        let mut callables = vec![
            CallableEntity::new(
                owner,
                "crate::body",
                true,
                false,
                true,
                false,
                vec![String::from("crate::body")],
            ),
            CallableEntity::new(
                bodyless,
                "ffi::bodyless",
                true,
                true,
                false,
                true,
                vec![String::from("ffi::bodyless")],
            ),
        ];
        let mut operations = vec![operation(owner, 1, false), operation(owner, 0, true)];
        let contracts = vec![CollectedSafetyContract::new(
            bodyless,
            Some(anchor(50, 55)),
            vec![SafetyRequirement::new(
                bodyless,
                0,
                "valid pointer",
                "the pointer is valid",
                Some(anchor(20, 25)),
            )],
        )];
        if reverse {
            files.reverse();
            anchors.reverse();
            callables.reverse();
            operations.reverse();
        }
        let program = CollectedProgram::try_new(files, anchors, callables, vec![body]).unwrap();
        CollectedArtifact::try_new(CollectedArtifactInput {
            program,
            unsafe_operations: operations,
            panic_contracts: Vec::new(),
            safety_contracts: contracts,
            mir_asserts: Vec::new(),
            marker_occurrences: Vec::new(),
        })
        .unwrap()
    }

    fn empty_artifact() -> CollectedArtifact {
        let program =
            CollectedProgram::try_new(Vec::new(), Vec::new(), Vec::new(), Vec::new()).unwrap();
        CollectedArtifact::try_new(CollectedArtifactInput {
            program,
            unsafe_operations: Vec::new(),
            panic_contracts: Vec::new(),
            safety_contracts: Vec::new(),
            mir_asserts: Vec::new(),
            marker_occurrences: Vec::new(),
        })
        .unwrap()
    }

    fn collect(
        artifact: &CollectedArtifact,
    ) -> (
        AnalysisRegistry<CollectedArtifact>,
        crate::analysis::facts::encoded::ArtifactFactIr,
    ) {
        let mut registry = AnalysisRegistry::<CollectedArtifact>::new();
        registry.install(&CoreProgramCollectionPack).unwrap();
        registry.install(&SafetyCollectionPack).unwrap();
        let mut builder = ArtifactDbBuilder::new();
        registry
            .run_artifact_passes(artifact, &mut builder)
            .unwrap();
        let ir = builder.finalize(registry.schemas()).unwrap();
        (registry, ir)
    }

    fn safety_schema_ids() -> BTreeSet<SchemaId> {
        [
            SafetyContractFact::ID,
            SafetyRequirement::ID,
            UnsafeOperationEntity::ID,
            UnsafeOperationMacroExpansionEntity::ID,
            FunctionOwnsUnsafeOperation::ID,
            UnsafeOperationInSafetyEffectGroup::ID,
            UnsafeOperationHasSourceAnchor::ID,
            FunctionEntersUnsafeOperationMacroExpansion::ID,
            UnsafeOperationMacroExpansionEntersUnsafeOperationMacroExpansion::ID,
            UnsafeOperationMacroExpansionProducesUnsafeOperation::ID,
            UnsafeOperationMacroExpansionHasCallsite::ID,
        ]
        .into_iter()
        .map(|id| SchemaId::new(id).unwrap())
        .collect()
    }

    #[test]
    fn pack_registers_one_exclusive_safety_producer() {
        let mut registry = AnalysisRegistry::<CollectedArtifact>::new();
        registry.install(&CoreProgramCollectionPack).unwrap();
        registry.install(&SafetyCollectionPack).unwrap();

        let producer = registry
            .artifact_passes()
            .descriptors()
            .find(|descriptor| descriptor.id.as_str() == COLLECT_SAFETY_ARTIFACT_PASS)
            .unwrap();
        assert_eq!(
            producer.writes.iter().cloned().collect::<BTreeSet<_>>(),
            safety_schema_ids()
        );
        assert_eq!(
            registry
                .artifact_passes()
                .descriptors()
                .filter(|descriptor| {
                    descriptor
                        .writes
                        .iter()
                        .any(|schema| safety_schema_ids().contains(schema))
                })
                .count(),
            1
        );
    }

    #[test]
    fn empty_collection_materializes_every_safety_table() {
        let (_, ir) = collect(&empty_artifact());
        for schema in safety_schema_ids() {
            let table = ir
                .tables
                .iter()
                .find(|table| table.schema == schema)
                .unwrap();
            assert!(table.rows.is_empty());
        }
    }

    #[test]
    fn operations_and_contracts_emit_complete_deterministic_provenance() {
        let (registry, forward) = collect(&artifact(false));
        let (_, reversed) = collect(&artifact(true));
        assert_eq!(forward, reversed);

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
        assert_rows!(SafetyContractFact, 1);
        assert_rows!(SafetyRequirement, 1);
        assert_rows!(UnsafeOperationEntity, 2);
        assert_rows!(UnsafeOperationMacroExpansionEntity, 2);
        assert_rows!(FunctionOwnsUnsafeOperation, 2);
        assert_rows!(UnsafeOperationInSafetyEffectGroup, 2);
        assert_rows!(UnsafeOperationHasSourceAnchor, 2);
        assert_rows!(FunctionEntersUnsafeOperationMacroExpansion, 1);
        assert_rows!(
            UnsafeOperationMacroExpansionEntersUnsafeOperationMacroExpansion,
            1
        );
        assert_rows!(UnsafeOperationMacroExpansionProducesUnsafeOperation, 1);
        assert_rows!(UnsafeOperationMacroExpansionHasCallsite, 2);

        let contracts = view.facts::<SafetyContractFact>().unwrap();
        assert_eq!(
            contracts[0].metadata.producer.as_str(),
            COLLECT_SAFETY_ARTIFACT_PASS
        );
        assert!(contracts[0].metadata.owner.is_some());
        assert!(contracts[0].metadata.anchor.is_some());
        assert_eq!(contracts[0].metadata.requirements.len(), 1);
    }
}
