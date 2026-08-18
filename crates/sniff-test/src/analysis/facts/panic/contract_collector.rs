//! Sole artifact pass for documented panic contracts.

use super::contracts::{PanicContractFact, PanicRequirement};
use crate::analysis::collected::{CollectedArtifact, CollectedPanicContract};
use crate::analysis::facts::pack::{AnalysisPack, AnalysisRegistry, PackRegistrationError};
use crate::analysis::facts::pass::{
    ArtifactPass, PassDescriptor, PassError, PassInput, PassOutput,
};
use crate::analysis::facts::program::topology::CallableEntity;
use crate::analysis::facts::program::{SourceAnchorEntity, SourceAnchorKey};
use crate::analysis::facts::schema::{EntityHandle, PassId, RowSchema, SchemaId};

pub(crate) const COLLECT_PANIC_CONTRACTS_PASS: &str = "sniff-test.panic.collect-contracts";

/// Composition pack for the sole documented-panic-contract producer.
pub(crate) struct PanicContractCollectionPack;

impl AnalysisPack<CollectedArtifact> for PanicContractCollectionPack {
    fn register(
        &self,
        registry: &mut AnalysisRegistry<CollectedArtifact>,
    ) -> Result<(), PackRegistrationError> {
        super::contracts::register_artifact_schemas(registry)?;
        registry.register_artifact_pass(CollectPanicContracts)
    }
}

struct CollectPanicContracts;

impl ArtifactPass<CollectedArtifact> for CollectPanicContracts {
    fn descriptor(&self) -> PassDescriptor {
        PassDescriptor::new(PassId::new(COLLECT_PANIC_CONTRACTS_PASS).unwrap())
            .with_reads([schema::<CallableEntity>(), schema::<SourceAnchorEntity>()])
            .with_writes([schema::<PanicContractFact>(), schema::<PanicRequirement>()])
    }

    fn run(
        &mut self,
        cx: &CollectedArtifact,
        _input: PassInput<'_>,
        output: &mut PassOutput<'_>,
    ) -> Result<(), PassError> {
        for contract in cx.panic_contracts() {
            emit_contract(contract, output)?;
        }
        Ok(())
    }
}

fn schema<S: RowSchema>() -> SchemaId {
    SchemaId::new(S::ID).expect("built-in panic-contract schema IDs are valid")
}

fn emit_contract(
    contract: &CollectedPanicContract,
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
    output.insert_fact(&PanicContractFact::new(), metadata)
}

fn source_anchor_handle(anchor: &SourceAnchorKey) -> EntityHandle<SourceAnchorEntity> {
    EntityHandle::new(anchor.clone())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{COLLECT_PANIC_CONTRACTS_PASS, PanicContractCollectionPack};
    use crate::analysis::collected::{
        CollectedArtifact, CollectedArtifactInput, CollectedPanicContract, CollectedProgram,
    };
    use crate::analysis::facts::builder::ArtifactDbBuilder;
    use crate::analysis::facts::pack::AnalysisRegistry;
    use crate::analysis::facts::panic::contracts::{PanicContractFact, PanicRequirement};
    use crate::analysis::facts::program::collector::CoreProgramCollectionPack;
    use crate::analysis::facts::program::topology::CallableEntity;
    use crate::analysis::facts::program::{
        FunctionKey, SourceAnchorEntity, SourceAnchorKey, SourceFileEntity,
    };
    use crate::analysis::facts::schema::{RowSchema, SchemaId};
    use crate::analysis::facts::view::ArtifactDbView;
    use crate::namespace::StableDefPathHash;

    fn definition(value: u128) -> StableDefPathHash {
        serde_json::from_str(&format!("\"{value:032x}\"")).expect("valid definition hash")
    }

    fn owner(value: u128) -> FunctionKey {
        FunctionKey::new(definition(value), None)
    }

    fn anchor(start: u64, end: u64) -> SourceAnchorKey {
        SourceAnchorKey::new("src/lib.rs", start, end)
    }

    fn artifact(reverse: bool) -> CollectedArtifact {
        let first_owner = owner(1);
        let second_owner = owner(2);
        let mut files = vec![SourceFileEntity::new(
            "src/lib.rs",
            "src/lib.rs",
            "verified-hash",
            100,
        )];
        let mut anchors = [anchor(0, 5), anchor(10, 15), anchor(20, 25)]
            .into_iter()
            .map(SourceAnchorEntity::new)
            .collect::<Vec<_>>();
        let mut callables = vec![
            CallableEntity::new(
                first_owner,
                "crate::first",
                false,
                true,
                false,
                false,
                vec![String::from("crate::first")],
            ),
            CallableEntity::new(
                second_owner,
                "crate::second",
                false,
                true,
                false,
                false,
                vec![String::from("crate::second")],
            ),
        ];
        let mut contracts = vec![
            CollectedPanicContract::new(first_owner, Some(anchor(0, 5)), Vec::new()),
            CollectedPanicContract::new(
                second_owner,
                None,
                vec![
                    PanicRequirement::new(
                        second_owner,
                        1,
                        "invalid",
                        "the input is invalid",
                        Some(anchor(20, 25)),
                    ),
                    PanicRequirement::new(
                        second_owner,
                        0,
                        "empty",
                        "the input is empty",
                        Some(anchor(10, 15)),
                    ),
                ],
            ),
        ];
        if reverse {
            files.reverse();
            anchors.reverse();
            callables.reverse();
            contracts.reverse();
        }
        let program = CollectedProgram::try_new(files, anchors, callables, Vec::new()).unwrap();
        CollectedArtifact::try_new(CollectedArtifactInput {
            program,
            unsafe_operations: Vec::new(),
            panic_contracts: contracts,
            safety_contracts: Vec::new(),
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
        registry.install(&PanicContractCollectionPack).unwrap();
        let mut builder = ArtifactDbBuilder::new();
        registry
            .run_artifact_passes(artifact, &mut builder)
            .unwrap();
        let ir = builder.finalize(registry.schemas()).unwrap();
        (registry, ir)
    }

    fn panic_schema_ids() -> BTreeSet<SchemaId> {
        [PanicContractFact::ID, PanicRequirement::ID]
            .into_iter()
            .map(|id| SchemaId::new(id).unwrap())
            .collect()
    }

    #[test]
    fn pack_registers_one_exclusive_panic_contract_producer() {
        let mut registry = AnalysisRegistry::<CollectedArtifact>::new();
        registry.install(&CoreProgramCollectionPack).unwrap();
        registry.install(&PanicContractCollectionPack).unwrap();

        let producer = registry
            .artifact_passes()
            .descriptors()
            .find(|descriptor| descriptor.id.as_str() == COLLECT_PANIC_CONTRACTS_PASS)
            .unwrap();
        assert_eq!(
            producer.writes.iter().cloned().collect::<BTreeSet<_>>(),
            panic_schema_ids()
        );
        assert_eq!(
            registry
                .artifact_passes()
                .descriptors()
                .filter(|descriptor| {
                    descriptor
                        .writes
                        .iter()
                        .any(|schema| panic_schema_ids().contains(schema))
                })
                .count(),
            1
        );
    }

    #[test]
    fn empty_collection_materializes_both_panic_contract_tables() {
        let (_, ir) = collect(&empty_artifact());
        for schema in panic_schema_ids() {
            let table = ir
                .tables
                .iter()
                .find(|table| table.schema == schema)
                .unwrap();
            assert!(table.rows.is_empty());
        }
    }

    #[test]
    fn contracts_emit_deterministically_with_owner_anchor_and_requirements() {
        let (registry, forward) = collect(&artifact(false));
        let (_, reversed) = collect(&artifact(true));
        assert_eq!(forward, reversed);

        let view = ArtifactDbView::open(&forward, registry.schemas()).unwrap();
        let contracts = view.facts::<PanicContractFact>().unwrap();
        assert_eq!(contracts.len(), 2);
        assert_eq!(view.table::<PanicRequirement>().unwrap().len(), 2);
        assert_eq!(
            contracts[0].metadata.producer.as_str(),
            COLLECT_PANIC_CONTRACTS_PASS
        );
        assert!(
            contracts
                .iter()
                .all(|contract| contract.metadata.owner.is_some())
        );
        assert_eq!(
            contracts
                .iter()
                .filter(|contract| contract.metadata.anchor.is_some())
                .count(),
            1
        );
        assert_eq!(
            contracts
                .iter()
                .map(|contract| contract.metadata.requirements.len())
                .sum::<usize>(),
            2
        );
    }
}
