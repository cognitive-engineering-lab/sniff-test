//! Documented panic-contract declarations and their open requirements.
//!
//! One empty fact row represents one callable's declaration boundary. Generic
//! [`crate::analysis::facts::builder::FactMeta`] carries its owner, source
//! anchor, and independently typed requirement rows, so an empty `# Panics`
//! section remains representable without a domain-specific core enum.

use serde::{Deserialize, Serialize};

use crate::contracts::normalize_requirement_name;

use super::super::pack::{AnalysisRegistry, PackRegistrationError};
use super::super::program::{FunctionKey, SourceAnchorKey};
use super::super::schema::{FactSchema, RequirementSchema, RowSchema};

/// One documented `# Panics` declaration attached to a callable.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct PanicContractFact {}

impl RowSchema for PanicContractFact {
    const ID: &'static str = "sniff-test.panic.contract";
    const VERSION: u32 = 1;
}

impl FactSchema for PanicContractFact {}

impl PanicContractFact {
    /// Creates a declaration row; ownership and contents live in fact metadata.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {}
    }
}

/// One source-ordered condition occurrence declared by a `# Panics` contract.
///
/// Owner and ordinal are part of row identity so repeated declarations remain
/// distinct. Consumers derive normalized lookup names from the preserved raw
/// spelling and sort a contract's referenced rows by [`Self::ordinal`].
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct PanicRequirement {
    owner: FunctionKey,
    ordinal: u32,
    name: String,
    condition: String,
    source_anchor: Option<SourceAnchorKey>,
}

impl RowSchema for PanicRequirement {
    const ID: &'static str = "sniff-test.panic.requirement.contract";
    const VERSION: u32 = 1;
}

impl RequirementSchema for PanicRequirement {}

impl PanicRequirement {
    /// Creates one declaration occurrence while preserving human text.
    #[must_use]
    pub(crate) fn new(
        owner: FunctionKey,
        ordinal: u32,
        name: impl Into<String>,
        condition: impl Into<String>,
        source_anchor: Option<SourceAnchorKey>,
    ) -> Self {
        Self {
            owner,
            ordinal,
            name: name.into(),
            condition: condition.into(),
            source_anchor,
        }
    }

    #[must_use]
    pub(crate) const fn owner(&self) -> &FunctionKey {
        &self.owner
    }

    #[must_use]
    pub(crate) const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    #[must_use]
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub(crate) fn normalized_name(&self) -> String {
        normalize_requirement_name(&self.name)
    }

    #[must_use]
    pub(crate) fn condition(&self) -> &str {
        &self.condition
    }

    #[must_use]
    pub(crate) const fn source_anchor(&self) -> Option<&SourceAnchorKey> {
        self.source_anchor.as_ref()
    }
}

/// Registers panic-contract rows emitted at the artifact-collection stage.
pub(crate) fn register_artifact_schemas<C: ?Sized>(
    registry: &mut AnalysisRegistry<C>,
) -> Result<(), PackRegistrationError> {
    registry.register_fact::<PanicContractFact>()?;
    registry.register_requirement::<PanicRequirement>()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{PanicContractFact, PanicRequirement, register_artifact_schemas};
    use crate::analysis::facts::builder::{ArtifactDbBuilder, FactMeta};
    use crate::analysis::facts::collection::CollectedArtifactSchemaPack;
    use crate::analysis::facts::encoded::TableKind;
    use crate::analysis::facts::human::HumanEvidencePack;
    use crate::analysis::facts::pack::AnalysisRegistry;
    use crate::analysis::facts::panic::rules::PanicPack;
    use crate::analysis::facts::program::{
        CoreProgramPack, FunctionKey, SourceAnchorEntity, SourceAnchorKey, topology::CallableEntity,
    };
    use crate::analysis::facts::schema::{PassId, RowSchema};
    use crate::analysis::facts::view::ArtifactDbView;
    use crate::namespace::StableDefPathHash;

    fn definition(value: &str) -> StableDefPathHash {
        serde_json::from_str(&format!("\"{value}\"")).expect("valid definition hash")
    }

    #[test]
    fn permanent_schema_and_panic_evaluation_packs_compose() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        registry.install(&HumanEvidencePack).unwrap();
        registry.install(&PanicPack).unwrap();

        assert_eq!(
            registry
                .schemas()
                .descriptor_for::<PanicContractFact>()
                .unwrap()
                .kind(),
            TableKind::Fact
        );
        assert_eq!(
            registry
                .schemas()
                .descriptor_for::<PanicRequirement>()
                .unwrap()
                .kind(),
            TableKind::Requirement
        );
    }

    #[test]
    fn contract_and_requirement_have_independent_canonical_schemas() {
        let contract = PanicContractFact::new();
        let owner = FunctionKey::new(definition("00000000000000000000000000000001"), None);
        let source_anchor = SourceAnchorKey::new("source.rs", 30, 48);
        let requirement = PanicRequirement::new(
            owner,
            2,
            "  Index_In-Bounds  ",
            "the index is less than the collection length",
            Some(source_anchor.clone()),
        );

        assert_ne!(PanicContractFact::ID, PanicRequirement::ID);
        assert_eq!(serde_json::to_value(contract).unwrap(), json!({}));
        assert_eq!(
            serde_json::to_value(&requirement).unwrap(),
            json!({
                "owner": {
                    "definition": "00000000000000000000000000000001",
                    "instance": null,
                },
                "ordinal": 2,
                "name": "  Index_In-Bounds  ",
                "condition": "the index is less than the collection length",
                "source-anchor": {
                    "file": "source.rs",
                    "byte-start": 30,
                    "byte-end": 48,
                },
            })
        );
        assert_eq!(requirement.owner(), &owner);
        assert_eq!(requirement.ordinal(), 2);
        assert_eq!(requirement.name(), "  Index_In-Bounds  ");
        assert_eq!(requirement.normalized_name(), "index in bounds");
        assert_eq!(
            requirement.condition(),
            "the index is less than the collection length"
        );
        assert_eq!(requirement.source_anchor(), Some(&source_anchor));
    }

    #[test]
    fn requirement_occurrences_preserve_spelling_order_and_multiplicity() {
        let mut registry = AnalysisRegistry::<()>::new();
        register_artifact_schemas(&mut registry).unwrap();
        let mut builder = ArtifactDbBuilder::new();
        let owner = FunctionKey::new(definition("00000000000000000000000000000001"), None);

        let occurrences = [
            PanicRequirement::new(
                owner,
                0,
                "Index_In-Bounds",
                "condition a",
                Some(SourceAnchorKey::new("source.rs", 10, 20)),
            ),
            PanicRequirement::new(
                owner,
                1,
                "Index_In-Bounds",
                "condition a",
                Some(SourceAnchorKey::new("source.rs", 30, 40)),
            ),
            PanicRequirement::new(owner, 2, "index in bounds", "condition b", None),
        ];
        for occurrence in &occurrences {
            builder.insert_requirement(occurrence).unwrap();
        }
        builder.insert_requirement(&occurrences[0]).unwrap();

        let artifact = builder.finalize(registry.schemas()).unwrap();
        let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
        let mut requirements = view
            .table::<PanicRequirement>()
            .unwrap()
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        requirements.sort_by_key(PanicRequirement::ordinal);

        assert_eq!(requirements.len(), 3);
        assert!(
            requirements
                .iter()
                .all(|row| row.normalized_name() == "index in bounds")
        );
        assert_eq!(
            requirements
                .iter()
                .map(|row| (row.ordinal(), row.name(), row.condition()))
                .collect::<Vec<_>>(),
            vec![
                (0, "Index_In-Bounds", "condition a"),
                (1, "Index_In-Bounds", "condition a"),
                (2, "index in bounds", "condition b"),
            ]
        );
        assert_ne!(
            requirements[0].source_anchor(),
            requirements[1].source_anchor()
        );
    }

    #[test]
    fn bodyless_callable_can_own_contract_anchor_and_requirement_occurrences() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CoreProgramPack).unwrap();
        register_artifact_schemas(&mut registry).unwrap();
        let mut builder = ArtifactDbBuilder::new();

        let function_key = FunctionKey::new(definition("00000000000000000000000000000001"), None);
        let callable = builder
            .insert_entity(&CallableEntity::new(
                function_key,
                "crate::fallible",
                false,
                true,
                false,
                true,
                vec![String::from("crate::fallible")],
            ))
            .unwrap();
        let anchor = builder
            .insert_entity(&SourceAnchorEntity::new(SourceAnchorKey::new(
                "source.rs",
                10,
                20,
            )))
            .unwrap();
        let first_anchor = SourceAnchorKey::new("source.rs", 30, 35);
        let second_anchor = SourceAnchorKey::new("source.rs", 36, 43);
        builder
            .insert_entity(&SourceAnchorEntity::new(first_anchor.clone()))
            .unwrap();
        builder
            .insert_entity(&SourceAnchorEntity::new(second_anchor.clone()))
            .unwrap();
        let first = builder
            .insert_requirement(&PanicRequirement::new(
                function_key,
                0,
                "empty",
                "the input is empty",
                Some(first_anchor),
            ))
            .unwrap();
        let second = builder
            .insert_requirement(&PanicRequirement::new(
                function_key,
                1,
                "invalid",
                "the input is invalid",
                Some(second_anchor),
            ))
            .unwrap();
        let meta = FactMeta::new(PassId::new("test.panic.contracts").unwrap())
            .with_owner(&callable)
            .unwrap()
            .with_anchor(&anchor)
            .unwrap()
            .with_requirement(&first)
            .unwrap()
            .with_requirement(&second)
            .unwrap();
        builder
            .insert_fact(&PanicContractFact::new(), meta)
            .unwrap();

        let artifact = builder.finalize(registry.schemas()).unwrap();
        let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
        let contracts = view.facts::<PanicContractFact>().unwrap();

        assert_eq!(contracts.len(), 1);
        assert_eq!(contracts[0].metadata.owner.as_ref().unwrap().row, 0);
        assert_eq!(contracts[0].metadata.anchor.as_ref().unwrap().row, 0);
        assert_eq!(contracts[0].metadata.requirements.len(), 2);
        assert_eq!(view.table::<PanicRequirement>().unwrap().len(), 2);
    }
}
