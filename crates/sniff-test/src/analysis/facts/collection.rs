//! Composition root for policy-neutral artifact collection.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use super::builder::{ArtifactDbBuilder, BuildError};
use super::encoded::ArtifactFactIr;
use super::human::markers::HumanMarkerCollectionPack;
use super::human::markers::HumanMarkerPack;
use super::pack::{AnalysisPack, AnalysisRegistry, PackRegistrationError};
use super::panic::assertion_collector::{
    PanicAssertionCollectionPack, register_artifact_schemas as register_assertion_schemas,
};
use super::panic::contract_collector::PanicContractCollectionPack;
use super::panic::contracts;
use super::pass::PassPipelineError;
use super::program::CoreProgramPack;
use super::program::collector::CoreProgramCollectionPack;
use super::safety::SafetyPack;
use super::safety::collector::SafetyCollectionPack;
use crate::analysis::collected::CollectedArtifact;

/// All permanent, policy-neutral artifact passes migrated to typed collection.
pub(crate) struct CollectedArtifactPack;

impl AnalysisPack<CollectedArtifact> for CollectedArtifactPack {
    fn register(
        &self,
        registry: &mut AnalysisRegistry<CollectedArtifact>,
    ) -> Result<(), PackRegistrationError> {
        registry.install(&CoreProgramCollectionPack)?;
        registry.install(&PanicContractCollectionPack)?;
        registry.install(&PanicAssertionCollectionPack)?;
        registry.install(&SafetyCollectionPack)?;
        registry.install(&HumanMarkerCollectionPack)
    }
}

/// Schema-only permanent artifact composition shared by cache and collection.
pub(crate) struct CollectedArtifactSchemaPack;

impl<C: ?Sized> AnalysisPack<C> for CollectedArtifactSchemaPack {
    fn register(&self, registry: &mut AnalysisRegistry<C>) -> Result<(), PackRegistrationError> {
        registry.install(&CoreProgramPack)?;
        registry.install(&SafetyPack)?;
        registry.install(&HumanMarkerPack)?;
        contracts::register_artifact_schemas(registry)?;
        register_assertion_schemas(registry)
    }
}

/// Runs every permanent typed collector and finalizes one canonical artifact.
pub(crate) fn collect_artifact_facts(
    artifact: &CollectedArtifact,
) -> Result<ArtifactFactIr, CollectedArtifactCollectionError> {
    let mut registry = AnalysisRegistry::<CollectedArtifact>::new();
    registry
        .install(&CollectedArtifactPack)
        .map_err(CollectedArtifactCollectionError::Registration)?;
    let mut builder = ArtifactDbBuilder::new();
    registry
        .run_artifact_passes(artifact, &mut builder)
        .map_err(CollectedArtifactCollectionError::Collection)?;
    builder
        .finalize(registry.schemas())
        .map_err(CollectedArtifactCollectionError::Finalization)
}

/// Failure at the single typed artifact-collection boundary.
#[derive(Debug)]
pub(crate) enum CollectedArtifactCollectionError {
    Registration(PackRegistrationError),
    Collection(PassPipelineError),
    Finalization(BuildError),
}

impl Display for CollectedArtifactCollectionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registration(_) => {
                formatter.write_str("typed artifact collection could not initialize")
            }
            Self::Collection(PassPipelineError::Run(run)) => {
                write!(
                    formatter,
                    "typed artifact collection failed: {}",
                    run.source
                )
            }
            Self::Collection(_) => formatter.write_str("typed artifact collection failed"),
            Self::Finalization(_) => {
                formatter.write_str("typed artifact facts could not be finalized")
            }
        }
    }
}

impl Error for CollectedArtifactCollectionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Registration(source) => Some(source),
            Self::Collection(source) => Some(source),
            Self::Finalization(source) => Some(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{CollectedArtifactPack, CollectedArtifactSchemaPack, collect_artifact_facts};
    use crate::analysis::collected::{CollectedArtifact, CollectedArtifactInput, CollectedProgram};
    use crate::analysis::facts::human::markers::MarkerOccurrenceEntity;
    use crate::analysis::facts::pack::AnalysisRegistry;
    use crate::analysis::facts::panic::assertion_collector::COLLECT_MIR_ASSERTS_PASS;
    use crate::analysis::facts::panic::contract_collector::COLLECT_PANIC_CONTRACTS_PASS;
    use crate::analysis::facts::panic::model::MirAssertFact;
    use crate::analysis::facts::program::FunctionEntity;
    use crate::analysis::facts::safety::SafetyContractFact;
    use crate::analysis::facts::safety::collector::COLLECT_SAFETY_ARTIFACT_PASS;
    use crate::analysis::facts::safety::operations::UnsafeOperationEntity;
    use crate::analysis::facts::schema::RowSchema;

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

    #[test]
    fn combined_pack_schedules_every_permanent_collector_and_materializes_empty_tables() {
        let artifact = empty_artifact();
        let mut registry = AnalysisRegistry::new();
        registry.install(&CollectedArtifactPack).unwrap();

        let pass_ids = registry
            .artifact_passes()
            .descriptors()
            .map(|descriptor| descriptor.id.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            pass_ids,
            BTreeSet::from([
                "sniff-test.core.collect-program",
                "sniff-test.human.collect-markers",
                COLLECT_MIR_ASSERTS_PASS,
                COLLECT_PANIC_CONTRACTS_PASS,
                COLLECT_SAFETY_ARTIFACT_PASS,
            ])
        );

        let facts = collect_artifact_facts(&artifact).unwrap();
        for schema in [
            FunctionEntity::ID,
            MarkerOccurrenceEntity::ID,
            MirAssertFact::ID,
            SafetyContractFact::ID,
            UnsafeOperationEntity::ID,
        ] {
            let table = facts
                .tables
                .iter()
                .find(|table| table.schema.as_str() == schema)
                .unwrap_or_else(|| panic!("missing materialized table {schema}"));
            assert!(table.rows.is_empty(), "{schema} was not empty");
        }
    }

    #[test]
    fn schema_only_pack_matches_permanent_collector_schemas() {
        let mut collection_registry = AnalysisRegistry::<CollectedArtifact>::new();
        collection_registry.install(&CollectedArtifactPack).unwrap();
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();

        let descriptors = |registry: &crate::analysis::facts::registry::SchemaRegistry| {
            registry
                .descriptors()
                .map(|descriptor| {
                    (
                        descriptor.id().clone(),
                        descriptor.version(),
                        descriptor.kind(),
                        descriptor.relation_endpoints().cloned(),
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            descriptors(collection_registry.schemas()),
            descriptors(registry.schemas()),
            "schema-only cache registry drifted from permanent collectors"
        );

        for schema in [
            FunctionEntity::ID,
            MarkerOccurrenceEntity::ID,
            MirAssertFact::ID,
            SafetyContractFact::ID,
            UnsafeOperationEntity::ID,
        ] {
            assert!(
                registry
                    .schemas()
                    .descriptors()
                    .any(|descriptor| descriptor.id().as_str() == schema),
                "missing permanent schema {schema}"
            );
        }
    }
}
