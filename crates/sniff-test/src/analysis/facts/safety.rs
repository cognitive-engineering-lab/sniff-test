//! Safety-pack artifact schemas.

mod call_issues;
pub(crate) mod collector;
mod completeness;
mod contract_index;
mod evidence_issues;
mod operation_issues;
pub(crate) mod operations;
mod root_inputs;
mod root_issues;

#[allow(
    unused_imports,
    reason = "the typed safety evaluator consumes call issues in the next slice"
)]
pub(crate) use call_issues::{
    DuplicateSafetyCallRequirementIssue, IndirectSafetyCallBoundaryIssue, SafetyCallIssueKind,
    SafetyCallIssuePack, UnsatisfiedSafetyCallIssue,
};
#[allow(
    unused_imports,
    reason = "the typed safety evaluator consumes completeness reports in the next slice"
)]
pub(crate) use completeness::{
    SafetyAnalysisIncompleteIssue, SafetyCompletenessOutcome, SafetyCompletenessPack,
    SafetyCompletenessReason,
};
#[allow(
    unused_imports,
    reason = "typed safety root preparation consumes the effective contract index next"
)]
pub(crate) use contract_index::{
    EffectiveSafetyContract, WorkspaceEffectiveSafetyContracts,
    WorkspaceEffectiveSafetyContractsError,
};
#[allow(
    unused_imports,
    reason = "the typed safety authority registry installs evidence coordination in the next slice"
)]
pub(crate) use evidence_issues::SafetyEvidenceUsePack;
#[allow(
    unused_imports,
    reason = "the typed safety evaluator consumes unsafe-operation issues in the next slice"
)]
pub(crate) use operation_issues::{SafetyOperationIssuePack, UnsatisfiedUnsafeOperationIssue};
#[allow(
    unused_imports,
    reason = "the typed safety evaluator consumes root preparation in the next slice"
)]
pub(crate) use root_inputs::{
    EmittedSafetyRoot, PreparedSafetyRoot, PreparedSafetyRootBatch, SafetyBoundary,
    SafetyContractCallBoundary, SafetyRootInputError, SafetyRootInputs, SafetyRootRequest,
    safety_domain,
};
#[allow(
    unused_imports,
    reason = "the typed safety evaluator consumes root issues in the next slice"
)]
pub(crate) use root_issues::{
    DuplicateSafetyRootRequirementIssue, MissingSafetyDocsIssue, SafetyRootIssuePack,
};

use serde::{Deserialize, Serialize};

use crate::contracts::normalize_requirement_name;

use super::pack::{AnalysisPack, AnalysisRegistry, PackRegistrationError};
use super::program::{FunctionKey, SourceAnchorKey};
use super::schema::{FactSchema, RequirementSchema, RowSchema};

/// One declared `# Safety` contract boundary.
///
/// Requirement identity and payload live in independently typed
/// [`SafetyRequirement`] rows referenced through this fact's metadata. The
/// unit payload deliberately preserves an empty contract section.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct SafetyContractFact {}

impl RowSchema for SafetyContractFact {
    const ID: &'static str = "sniff-test.safety.contract";
    const VERSION: u32 = 1;
}

impl FactSchema for SafetyContractFact {}

impl SafetyContractFact {
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {}
    }
}

/// One source-ordered requirement occurrence declared by a `# Safety` contract.
///
/// Owner and ordinal prevent repeated declarations from collapsing. Consumers
/// derive normalized lookup names from the raw spelling and sort the contract's
/// referenced rows by [`Self::ordinal`].
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct SafetyRequirement {
    owner: FunctionKey,
    ordinal: u32,
    name: String,
    condition: String,
    source_anchor: Option<SourceAnchorKey>,
}

impl RowSchema for SafetyRequirement {
    const ID: &'static str = "sniff-test.safety.requirement.contract";
    const VERSION: u32 = 1;
}

impl RequirementSchema for SafetyRequirement {}

impl SafetyRequirement {
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

/// Registers the independently versioned safety artifact schemas.
///
/// [`CoreProgramPack`](super::program::CoreProgramPack) must be installed first
/// because operation provenance targets core function, group, and source rows.
pub(crate) fn register_artifact_schemas<C: ?Sized>(
    registry: &mut AnalysisRegistry<C>,
) -> Result<(), PackRegistrationError> {
    registry.register_fact::<SafetyContractFact>()?;
    registry.register_requirement::<SafetyRequirement>()?;
    operations::register(registry)?;
    Ok(())
}

/// Safety analysis pack, extended with rules and renderers in later slices.
///
/// Install [`CoreProgramPack`](super::program::CoreProgramPack) before this pack.
pub(crate) struct SafetyPack;

impl<C: ?Sized> AnalysisPack<C> for SafetyPack {
    fn register(&self, registry: &mut AnalysisRegistry<C>) -> Result<(), PackRegistrationError> {
        register_artifact_schemas(registry)
    }
}

#[cfg(test)]
mod tests {
    use super::{SafetyContractFact, SafetyPack, SafetyRequirement};
    use crate::analysis::facts::builder::{ArtifactDbBuilder, FactMeta};
    use crate::analysis::facts::encoded::TableKind;
    use crate::analysis::facts::pack::AnalysisRegistry;
    use crate::analysis::facts::program::{
        CoreProgramPack, FunctionKey, SourceAnchorEntity, SourceAnchorKey, topology::CallableEntity,
    };
    use crate::analysis::facts::schema::{PassId, RowSchema, SchemaId};
    use crate::analysis::facts::view::ArtifactDbView;
    use crate::namespace::StableDefPathHash;

    fn definition(value: &str) -> StableDefPathHash {
        serde_json::from_str(&format!("\"{value}\"")).expect("valid definition hash")
    }

    fn owner() -> FunctionKey {
        FunctionKey::new(definition("00000000000000000000000000000001"), None)
    }

    #[test]
    fn safety_pack_registers_an_empty_contract_and_independent_requirements() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CoreProgramPack).unwrap();
        registry.install(&SafetyPack).unwrap();

        for (id, kind) in [
            (SafetyContractFact::ID, TableKind::Fact),
            (SafetyRequirement::ID, TableKind::Requirement),
        ] {
            let descriptor = registry
                .schemas()
                .descriptor(&SchemaId::new(id).unwrap())
                .expect("safety schema is registered");
            assert_eq!(descriptor.kind(), kind);
        }

        let empty = SafetyContractFact::new();
        assert_eq!(empty, SafetyContractFact::new());

        let source_anchor = SourceAnchorKey::new("source.rs", 10, 24);
        let first = SafetyRequirement::new(
            owner(),
            0,
            "  Valid_Pointer  ",
            "the pointer is valid",
            Some(source_anchor.clone()),
        );
        let duplicate = first.clone();
        let distinct = SafetyRequirement::new(
            owner(),
            1,
            "valid pointer",
            "the pointer is valid",
            Some(SourceAnchorKey::new("source.rs", 30, 44)),
        );
        assert_eq!(first, duplicate);
        assert_ne!(first, distinct);
        assert_eq!(first.normalized_name(), "valid pointer");
        assert_eq!(first.name(), "  Valid_Pointer  ");
        assert_eq!(first.owner(), &owner());
        assert_eq!(first.ordinal(), 0);
        assert_eq!(first.condition(), "the pointer is valid");
        assert_eq!(first.source_anchor(), Some(&source_anchor));
    }

    #[test]
    fn requirement_occurrences_preserve_spelling_order_and_multiplicity() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CoreProgramPack).unwrap();
        registry.install(&SafetyPack).unwrap();
        let mut builder = ArtifactDbBuilder::new();

        let requirements = [
            SafetyRequirement::new(owner(), 0, "Valid_Pointer", "condition a", None),
            SafetyRequirement::new(owner(), 1, "valid pointer", "condition a", None),
            SafetyRequirement::new(owner(), 2, "valid pointer", "condition b", None),
        ];
        for requirement in &requirements {
            builder.insert_requirement(requirement).unwrap();
        }
        builder.insert_requirement(&requirements[0]).unwrap();

        let artifact = builder.finalize(registry.schemas()).unwrap();
        let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
        let mut requirements = view
            .table::<SafetyRequirement>()
            .unwrap()
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        requirements.sort_by_key(SafetyRequirement::ordinal);

        assert_eq!(requirements.len(), 3);
        assert!(
            requirements
                .iter()
                .all(|row| row.normalized_name() == "valid pointer")
        );
        assert_eq!(
            requirements
                .iter()
                .map(|row| (row.ordinal(), row.name(), row.condition()))
                .collect::<Vec<_>>(),
            vec![
                (0, "Valid_Pointer", "condition a"),
                (1, "valid pointer", "condition a"),
                (2, "valid pointer", "condition b"),
            ]
        );
    }

    #[test]
    fn bodyless_callable_can_own_an_empty_safety_contract() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CoreProgramPack).unwrap();
        registry.install(&SafetyPack).unwrap();
        let mut builder = ArtifactDbBuilder::new();
        let owner = owner();

        let callable = builder
            .insert_entity(&CallableEntity::new(
                owner,
                "ffi::boundary",
                true,
                true,
                false,
                true,
                vec![String::from("ffi::boundary")],
            ))
            .unwrap();
        let anchor_key = SourceAnchorKey::new("source.rs", 10, 20);
        let anchor = builder
            .insert_entity(&SourceAnchorEntity::new(anchor_key))
            .unwrap();
        let meta = FactMeta::new(PassId::new("test.safety.contracts").unwrap())
            .with_owner(&callable)
            .unwrap()
            .with_anchor(&anchor)
            .unwrap();
        builder
            .insert_fact(&SafetyContractFact::new(), meta)
            .unwrap();

        let artifact = builder.finalize(registry.schemas()).unwrap();
        let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
        let contracts = view.facts::<SafetyContractFact>().unwrap();

        assert_eq!(contracts.len(), 1);
        assert_eq!(contracts[0].metadata.owner.as_ref().unwrap().row, 0);
        assert_eq!(contracts[0].metadata.anchor.as_ref().unwrap().row, 0);
        assert!(contracts[0].metadata.requirements.is_empty());
    }
}
