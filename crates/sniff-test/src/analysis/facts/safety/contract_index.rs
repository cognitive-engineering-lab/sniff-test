//! Exact-generation lookup of effective safety contract presence.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;

use super::{SafetyContractFact, SafetyRequirement};
use crate::analysis::facts::encoded::TableKind;
use crate::analysis::facts::program::FunctionKey;
use crate::analysis::facts::program::topology::CallableEntity;
use crate::analysis::facts::program::workspace_index::{
    WorkspaceProgramIndex, WorkspaceProgramIndexError,
};
use crate::analysis::facts::schema::{RowSchema, SchemaId};
use crate::analysis::facts::view::{ArtifactDbView, TypedFact, ViewError};
use crate::analysis::facts::workspace::{
    ArtifactScopeId, ScopedEntityId, ScopedEntityRef, ScopedRowRef, WorkspaceFactView,
    WorkspaceIdentity, WorkspaceViewError,
};
use crate::contracts::{ContractDocOverrides, safety_contract_doc_summary_from_markdown};

/// Immutable effective-contract lookup prepared for one exact workspace view.
#[derive(Clone, Debug)]
pub(crate) struct WorkspaceEffectiveSafetyContracts {
    workspace: Arc<WorkspaceIdentity>,
    overrides: ContractDocOverrides,
    raw_by_callable: BTreeMap<ScopedEntityId<CallableEntity>, ScopedRowRef>,
}

impl WorkspaceEffectiveSafetyContracts {
    pub(crate) fn open(
        workspace: &WorkspaceFactView<'_>,
        program: &WorkspaceProgramIndex,
        overrides: &ContractDocOverrides,
    ) -> Result<Self, WorkspaceEffectiveSafetyContractsError> {
        program
            .validate_workspace(workspace)
            .map_err(WorkspaceEffectiveSafetyContractsError::program)?;
        let mut raw_by_callable = BTreeMap::new();
        for scope in workspace.scopes() {
            let view = workspace
                .artifact(scope)
                .map_err(WorkspaceEffectiveSafetyContractsError::workspace)?;
            require_table::<SafetyContractFact>(scope, view, TableKind::Fact)?;
            require_table::<SafetyRequirement>(scope, view, TableKind::Requirement)?;
            let contracts = view.facts::<SafetyContractFact>().map_err(|source| {
                WorkspaceEffectiveSafetyContractsError::ReadContracts {
                    scope: scope.clone(),
                    source: Box::new(source),
                }
            })?;
            for contract in contracts {
                index_contract(workspace, program, scope, contract, &mut raw_by_callable)?;
            }
        }
        Ok(Self {
            workspace: workspace.identity(),
            overrides: overrides.clone(),
            raw_by_callable,
        })
    }

    pub(crate) fn validate_workspace(
        &self,
        workspace: &WorkspaceFactView<'_>,
    ) -> Result<(), WorkspaceEffectiveSafetyContractsError> {
        if workspace.has_identity(&self.workspace) {
            Ok(())
        } else {
            Err(WorkspaceEffectiveSafetyContractsError::WorkspaceMismatch)
        }
    }

    pub(crate) fn has_effective_safety_contract(
        &self,
        workspace: &WorkspaceFactView<'_>,
        callable: &ScopedEntityId<CallableEntity>,
    ) -> Result<bool, WorkspaceEffectiveSafetyContractsError> {
        self.validate_workspace(workspace)?;
        let data = workspace
            .entity::<CallableEntity>(&callable.erase())
            .map_err(
                |source| WorkspaceEffectiveSafetyContractsError::InvalidCallable {
                    callable: Box::new(callable.erase()),
                    source: Box::new(source),
                },
            )?;
        if let Some(markdown) = self
            .overrides
            .markdown_for_candidates(data.namespace_candidates())
        {
            return Ok(safety_contract_doc_summary_from_markdown(markdown).has_docs);
        }
        if self.raw_by_callable.contains_key(callable) {
            return Ok(true);
        }
        let generic = FunctionKey::new(data.key().definition(), None);
        if data.key().instance().is_none() {
            return Ok(false);
        }
        let generic = workspace
            .entity_id_by_key::<CallableEntity>(callable.scope(), &generic)
            .map_err(
                |source| WorkspaceEffectiveSafetyContractsError::InvalidCallable {
                    callable: Box::new(callable.erase()),
                    source: Box::new(source),
                },
            )?;
        Ok(generic.is_some_and(|generic| self.raw_by_callable.contains_key(&generic)))
    }
}

fn require_table<S: RowSchema>(
    scope: &ArtifactScopeId,
    view: ArtifactDbView<'_>,
    expected: TableKind,
) -> Result<(), WorkspaceEffectiveSafetyContractsError> {
    let schema = SchemaId::new(S::ID).expect("built-in safety schema IDs are valid");
    let descriptor = view.registry().descriptor(&schema).ok_or_else(|| {
        WorkspaceEffectiveSafetyContractsError::SchemaUnavailable {
            scope: scope.clone(),
            schema: schema.clone(),
        }
    })?;
    if descriptor.kind() != expected {
        return Err(WorkspaceEffectiveSafetyContractsError::InvalidTableKind {
            scope: scope.clone(),
            schema,
            found: descriptor.kind(),
        });
    }
    if view
        .artifact()
        .tables
        .binary_search_by(|table| table.schema.cmp(&schema))
        .is_err()
    {
        return Err(WorkspaceEffectiveSafetyContractsError::MissingTable {
            scope: scope.clone(),
            schema,
        });
    }
    Ok(())
}

fn index_contract(
    workspace: &WorkspaceFactView<'_>,
    program: &WorkspaceProgramIndex,
    scope: &ArtifactScopeId,
    contract: TypedFact<SafetyContractFact>,
    raw_by_callable: &mut BTreeMap<ScopedEntityId<CallableEntity>, ScopedRowRef>,
) -> Result<(), WorkspaceEffectiveSafetyContractsError> {
    let source = ScopedRowRef::new(scope.clone(), contract.fact.reference);
    let owner = contract
        .metadata
        .owner
        .map(|owner| ScopedEntityRef::new(scope.clone(), owner))
        .ok_or_else(|| WorkspaceEffectiveSafetyContractsError::MissingOwner {
            contract: source.clone(),
        })?;
    let callable = workspace
        .entity::<CallableEntity>(&owner)
        .map_err(
            |error| WorkspaceEffectiveSafetyContractsError::InvalidOwner {
                contract: source.clone(),
                owner: Box::new(owner.clone()),
                source: Box::new(error),
            },
        )?;
    let indexed_owner = program
        .exact_callable(scope, callable.key())
        .filter(|indexed| indexed.reference() == &owner)
        .ok_or_else(|| WorkspaceEffectiveSafetyContractsError::OwnerNotIndexed {
            contract: source.clone(),
            owner: Box::new(owner),
        })?;
    let owner = indexed_owner.id();
    if let Some(first) = raw_by_callable.get(&owner) {
        return Err(WorkspaceEffectiveSafetyContractsError::DuplicateOwner {
            owner: Box::new(owner),
            first: first.clone(),
            duplicate: source,
        });
    }
    raw_by_callable.insert(owner, source);
    Ok(())
}

/// Structured failure while preparing or querying effective safety contracts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WorkspaceEffectiveSafetyContractsError {
    WorkspaceMismatch,
    SchemaUnavailable {
        scope: ArtifactScopeId,
        schema: SchemaId,
    },
    InvalidTableKind {
        scope: ArtifactScopeId,
        schema: SchemaId,
        found: TableKind,
    },
    MissingTable {
        scope: ArtifactScopeId,
        schema: SchemaId,
    },
    Program {
        source: Box<WorkspaceProgramIndexError>,
    },
    Workspace {
        source: Box<WorkspaceViewError>,
    },
    ReadContracts {
        scope: ArtifactScopeId,
        source: Box<ViewError>,
    },
    MissingOwner {
        contract: ScopedRowRef,
    },
    InvalidOwner {
        contract: ScopedRowRef,
        owner: Box<ScopedEntityRef>,
        source: Box<WorkspaceViewError>,
    },
    OwnerNotIndexed {
        contract: ScopedRowRef,
        owner: Box<ScopedEntityRef>,
    },
    DuplicateOwner {
        owner: Box<ScopedEntityId<CallableEntity>>,
        first: ScopedRowRef,
        duplicate: ScopedRowRef,
    },
    InvalidCallable {
        callable: Box<ScopedEntityRef>,
        source: Box<WorkspaceViewError>,
    },
}

impl WorkspaceEffectiveSafetyContractsError {
    fn program(source: WorkspaceProgramIndexError) -> Self {
        Self::Program {
            source: Box::new(source),
        }
    }

    fn workspace(source: WorkspaceViewError) -> Self {
        Self::Workspace {
            source: Box::new(source),
        }
    }
}

impl Display for WorkspaceEffectiveSafetyContractsError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkspaceMismatch => formatter.write_str(
                "effective safety contract index belongs to a replacement workspace view",
            ),
            Self::SchemaUnavailable { scope, schema } => write!(
                formatter,
                "artifact scope `{scope}` has no registered safety schema `{schema}`"
            ),
            Self::InvalidTableKind {
                scope,
                schema,
                found,
            } => write!(
                formatter,
                "artifact scope `{scope}` registers safety schema `{schema}` as {found:?}"
            ),
            Self::MissingTable { scope, schema } => write!(
                formatter,
                "artifact scope `{scope}` is missing required safety table `{schema}`"
            ),
            Self::Program { .. } => formatter.write_str("permanent program index is invalid"),
            Self::Workspace { .. } => formatter.write_str("workspace artifact lookup failed"),
            Self::ReadContracts { scope, .. } => write!(
                formatter,
                "cannot read safety contracts in artifact scope `{scope}`"
            ),
            Self::MissingOwner { contract } => {
                write!(
                    formatter,
                    "safety contract {contract:?} has no callable owner"
                )
            }
            Self::InvalidOwner { contract, .. } => write!(
                formatter,
                "safety contract {contract:?} has an invalid callable owner"
            ),
            Self::OwnerNotIndexed { contract, .. } => write!(
                formatter,
                "safety contract {contract:?} owner is absent from the permanent program index"
            ),
            Self::DuplicateOwner { owner, .. } => {
                write!(
                    formatter,
                    "callable {owner:?} owns multiple safety contracts"
                )
            }
            Self::InvalidCallable { callable, .. } => {
                write!(formatter, "callable query {callable:?} is invalid")
            }
        }
    }
}

impl Error for WorkspaceEffectiveSafetyContractsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Program { source } => Some(source.as_ref()),
            Self::Workspace { source }
            | Self::InvalidOwner { source, .. }
            | Self::InvalidCallable { source, .. } => Some(source.as_ref()),
            Self::ReadContracts { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::super::SafetyContractFact;
    use super::{
        WorkspaceEffectiveSafetyContracts, WorkspaceEffectiveSafetyContractsError, index_contract,
    };
    use crate::analysis::facts::builder::{ArtifactDbBuilder, FactMeta};
    use crate::analysis::facts::collection::CollectedArtifactSchemaPack;
    use crate::analysis::facts::encoded::ArtifactFactIr;
    use crate::analysis::facts::pack::AnalysisRegistry;
    use crate::analysis::facts::program::FunctionKey;
    use crate::analysis::facts::program::topology::CallableEntity;
    use crate::analysis::facts::program::workspace_index::{
        VerifiedArtifactOwner, WorkspaceProgramIndex,
    };
    use crate::analysis::facts::schema::{PassId, RowSchema};
    use crate::analysis::facts::view::ArtifactDbView;
    use crate::analysis::facts::workspace::{ArtifactScopeId, WorkspaceFactView};
    use crate::contracts::ContractDocOverrides;
    use crate::namespace::{StableDefPathHash, StableInstanceHash};

    fn definition(stable_crate_id: u64, local: u64) -> StableDefPathHash {
        serde_json::from_str(&format!("\"{stable_crate_id:016x}{local:016x}\""))
            .expect("valid definition hash")
    }

    fn instance(value: u128) -> StableInstanceHash {
        serde_json::from_str(&format!("\"{value:032x}\"")).expect("valid instance hash")
    }

    fn callable_key(stable_crate_id: u64, local: u64, exact: Option<u128>) -> FunctionKey {
        FunctionKey::new(definition(stable_crate_id, local), exact.map(instance))
    }

    fn artifact(
        registry: &AnalysisRegistry<()>,
        callables: &[(FunctionKey, &str, &[&str])],
        contracts: &[FunctionKey],
    ) -> ArtifactFactIr {
        let mut builder = ArtifactDbBuilder::new();
        for descriptor in registry.schemas().descriptors() {
            builder.declare_table(descriptor).unwrap();
        }
        let mut handles = BTreeMap::new();
        for (key, path, candidates) in callables {
            let handle = builder
                .insert_entity(&CallableEntity::new(
                    *key,
                    *path,
                    false,
                    false,
                    false,
                    false,
                    candidates
                        .iter()
                        .map(|candidate| (*candidate).to_owned())
                        .collect(),
                ))
                .unwrap();
            handles.insert(*key, handle);
        }
        for owner in contracts {
            let metadata = FactMeta::new(PassId::new("test.safety.contract-index").unwrap())
                .with_owner(handles.get(owner).unwrap())
                .unwrap();
            builder
                .insert_fact(&SafetyContractFact::new(), metadata)
                .unwrap();
        }
        builder.finalize(registry.schemas()).unwrap()
    }

    fn workspace_and_program<'a>(
        artifact: &'a ArtifactFactIr,
        registry: &'a AnalysisRegistry<()>,
        stable_crate_id: u64,
    ) -> (
        ArtifactScopeId,
        WorkspaceFactView<'a>,
        WorkspaceProgramIndex,
    ) {
        let scope = ArtifactScopeId::for_in_memory(stable_crate_id, 0);
        let workspace = WorkspaceFactView::compose([(
            scope.clone(),
            ArtifactDbView::open(artifact, registry.schemas()).unwrap(),
        )])
        .unwrap();
        let program = WorkspaceProgramIndex::open(
            &workspace,
            [VerifiedArtifactOwner::new(scope.clone(), stable_crate_id)],
        )
        .unwrap();
        (scope, workspace, program)
    }

    fn contract_metadata_mut(
        artifact: &mut ArtifactFactIr,
    ) -> &mut crate::analysis::facts::encoded::FactIndexRow {
        artifact
            .fact_index
            .iter_mut()
            .find(|metadata| metadata.fact.schema.as_str() == SafetyContractFact::ID)
            .expect("fixture contains one safety contract")
    }

    #[test]
    fn raw_generic_contract_applies_to_exact_callable_in_the_same_scope() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let generic = callable_key(1, 1, None);
        let exact = callable_key(1, 1, Some(11));
        let artifact = artifact(
            &registry,
            &[
                (generic, "crate::generic", &["crate::generic"]),
                (exact, "crate::generic::<u8>", &["crate::generic"]),
            ],
            &[generic],
        );
        let scope = ArtifactScopeId::for_in_memory(1, 0);
        let workspace = WorkspaceFactView::compose([(
            scope.clone(),
            ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
        )])
        .unwrap();
        let program =
            WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 1)])
                .unwrap();
        let contracts = WorkspaceEffectiveSafetyContracts::open(
            &workspace,
            &program,
            &ContractDocOverrides::default(),
        )
        .unwrap();

        let generic = program.exact_callable(&scope, &generic).unwrap().id();
        let exact = program.exact_callable(&scope, &exact).unwrap().id();
        assert!(
            contracts
                .has_effective_safety_contract(&workspace, &generic)
                .unwrap()
        );
        assert!(
            contracts
                .has_effective_safety_contract(&workspace, &exact)
                .unwrap()
        );
    }

    #[test]
    fn raw_exact_contract_applies_only_to_that_exact_callable() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let generic = callable_key(2, 1, None);
        let first = callable_key(2, 1, Some(21));
        let sibling = callable_key(2, 1, Some(22));
        let artifact = artifact(
            &registry,
            &[
                (generic, "crate::generic", &["crate::generic"]),
                (first, "crate::generic::<u8>", &["crate::generic"]),
                (sibling, "crate::generic::<u16>", &["crate::generic"]),
            ],
            &[first],
        );
        let scope = ArtifactScopeId::for_in_memory(2, 0);
        let workspace = WorkspaceFactView::compose([(
            scope.clone(),
            ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
        )])
        .unwrap();
        let program =
            WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 2)])
                .unwrap();
        let contracts = WorkspaceEffectiveSafetyContracts::open(
            &workspace,
            &program,
            &ContractDocOverrides::default(),
        )
        .unwrap();

        let generic = program.exact_callable(&scope, &generic).unwrap().id();
        let first = program.exact_callable(&scope, &first).unwrap().id();
        let sibling = program.exact_callable(&scope, &sibling).unwrap().id();
        assert!(
            contracts
                .has_effective_safety_contract(&workspace, &first)
                .unwrap()
        );
        assert!(
            !contracts
                .has_effective_safety_contract(&workspace, &generic)
                .unwrap()
        );
        assert!(
            !contracts
                .has_effective_safety_contract(&workspace, &sibling)
                .unwrap()
        );
    }

    #[test]
    fn raw_contracts_never_cross_artifact_scopes() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let generic = callable_key(3, 1, None);
        let exact = callable_key(3, 1, Some(31));
        let with_contract = artifact(
            &registry,
            &[
                (generic, "dependency::generic", &["dependency::generic"]),
                (exact, "dependency::generic::<u8>", &["dependency::generic"]),
            ],
            &[generic],
        );
        let without_contract = artifact(
            &registry,
            &[
                (generic, "dependency::generic", &["dependency::generic"]),
                (exact, "dependency::generic::<u8>", &["dependency::generic"]),
            ],
            &[],
        );
        let first_scope = ArtifactScopeId::for_in_memory(3, 0);
        let second_scope = ArtifactScopeId::for_in_memory(4, 0);
        let workspace = WorkspaceFactView::compose([
            (
                first_scope.clone(),
                ArtifactDbView::open(&with_contract, registry.schemas()).unwrap(),
            ),
            (
                second_scope.clone(),
                ArtifactDbView::open(&without_contract, registry.schemas()).unwrap(),
            ),
        ])
        .unwrap();
        let program = WorkspaceProgramIndex::open(
            &workspace,
            [
                VerifiedArtifactOwner::new(first_scope, 3),
                VerifiedArtifactOwner::new(second_scope.clone(), 4),
            ],
        )
        .unwrap();
        let contracts = WorkspaceEffectiveSafetyContracts::open(
            &workspace,
            &program,
            &ContractDocOverrides::default(),
        )
        .unwrap();

        let exact = program.exact_callable(&second_scope, &exact).unwrap().id();
        assert!(
            !contracts
                .has_effective_safety_contract(&workspace, &exact)
                .unwrap()
        );
    }

    #[test]
    fn matching_override_fully_replaces_a_raw_generic_contract() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let generic = callable_key(5, 1, None);
        let exact = callable_key(5, 1, Some(51));
        let artifact = artifact(
            &registry,
            &[
                (generic, "dependency::generic", &["dependency::generic"]),
                (
                    exact,
                    "dependency::Widget::run",
                    &["dependency::Widget::run"],
                ),
            ],
            &[generic],
        );
        let scope = ArtifactScopeId::for_in_memory(5, 0);
        let workspace = WorkspaceFactView::compose([(
            scope.clone(),
            ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
        )])
        .unwrap();
        let program =
            WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 5)])
                .unwrap();
        let overrides = ContractDocOverrides::new(vec![(
            String::from("dependency::Widget::run"),
            String::from("# Notes\nNo contract here."),
        )])
        .unwrap();
        let contracts =
            WorkspaceEffectiveSafetyContracts::open(&workspace, &program, &overrides).unwrap();

        let exact = program.exact_callable(&scope, &exact).unwrap().id();
        assert!(
            !contracts
                .has_effective_safety_contract(&workspace, &exact)
                .unwrap()
        );
    }

    #[test]
    fn override_can_add_an_empty_safety_heading_and_is_snapshotted() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let callable = callable_key(6, 1, None);
        let artifact = artifact(
            &registry,
            &[(
                callable,
                "dependency::Widget::run",
                &["dependency::Widget::run"],
            )],
            &[],
        );
        let scope = ArtifactScopeId::for_in_memory(6, 0);
        let workspace = WorkspaceFactView::compose([(
            scope.clone(),
            ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
        )])
        .unwrap();
        let program =
            WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 6)])
                .unwrap();
        let overrides = ContractDocOverrides::new(vec![(
            String::from("dependency::Widget::run"),
            String::from("# Safety"),
        )])
        .unwrap();
        let contracts =
            WorkspaceEffectiveSafetyContracts::open(&workspace, &program, &overrides).unwrap();
        drop(overrides);

        let callable = program.exact_callable(&scope, &callable).unwrap().id();
        assert!(
            contracts
                .has_effective_safety_contract(&workspace, &callable)
                .unwrap()
        );
    }

    #[test]
    fn override_uses_reached_candidates_and_the_most_specific_pattern() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let generic = callable_key(7, 1, None);
        let exact = callable_key(7, 1, Some(71));
        let artifact = artifact(
            &registry,
            &[
                (generic, "dependency::generic", &["dependency::generic"]),
                (
                    exact,
                    "consumer::alias",
                    &["dependency::Widget::run", "consumer::alias"],
                ),
            ],
            &[],
        );
        let scope = ArtifactScopeId::for_in_memory(7, 0);
        let workspace = WorkspaceFactView::compose([(
            scope.clone(),
            ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
        )])
        .unwrap();
        let program =
            WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 7)])
                .unwrap();
        let overrides = ContractDocOverrides::new(vec![
            (
                String::from("dependency::**"),
                String::from("# Notes\nBroad override without a contract."),
            ),
            (
                String::from("dependency::Widget::run"),
                String::from("# Safety"),
            ),
        ])
        .unwrap();
        let contracts =
            WorkspaceEffectiveSafetyContracts::open(&workspace, &program, &overrides).unwrap();

        let exact = program.exact_callable(&scope, &exact).unwrap().id();
        assert!(
            contracts
                .has_effective_safety_contract(&workspace, &exact)
                .unwrap()
        );
    }

    #[test]
    fn replacement_workspace_is_rejected_at_open_and_query() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let key = callable_key(8, 1, None);
        let artifact = artifact(
            &registry,
            &[(key, "crate::callable", &["crate::callable"])],
            &[key],
        );
        let scope = ArtifactScopeId::for_in_memory(8, 0);
        let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
        let workspace = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
        let replacement = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
        let program =
            WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 8)])
                .unwrap();
        let contracts = WorkspaceEffectiveSafetyContracts::open(
            &workspace,
            &program,
            &ContractDocOverrides::default(),
        )
        .unwrap();
        let replacement_callable = replacement
            .entity_id_by_key::<CallableEntity>(&scope, &key)
            .unwrap()
            .unwrap();

        assert!(matches!(
            WorkspaceEffectiveSafetyContracts::open(
                &replacement,
                &program,
                &ContractDocOverrides::default()
            ),
            Err(WorkspaceEffectiveSafetyContractsError::Program { .. })
        ));
        assert!(matches!(
            contracts.validate_workspace(&replacement),
            Err(WorkspaceEffectiveSafetyContractsError::WorkspaceMismatch)
        ));
        assert!(matches!(
            contracts.has_effective_safety_contract(&replacement, &replacement_callable),
            Err(WorkspaceEffectiveSafetyContractsError::WorkspaceMismatch)
        ));
    }

    #[test]
    fn both_safety_producer_tables_must_be_present_in_every_scope() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let key = callable_key(9, 1, None);
        for missing in [SafetyContractFact::ID, super::super::SafetyRequirement::ID] {
            let mut artifact = artifact(
                &registry,
                &[(key, "crate::callable", &["crate::callable"])],
                &[key],
            );
            artifact
                .tables
                .retain(|table| table.schema.as_str() != missing);
            artifact
                .fact_index
                .retain(|metadata| metadata.fact.schema.as_str() != missing);
            let (_, workspace, program) = workspace_and_program(&artifact, &registry, 9);

            assert!(matches!(
                WorkspaceEffectiveSafetyContracts::open(
                    &workspace,
                    &program,
                    &ContractDocOverrides::default()
                ),
                Err(WorkspaceEffectiveSafetyContractsError::MissingTable { ref schema, .. })
                    if schema.as_str() == missing
            ));
        }
    }

    #[test]
    fn missing_wrong_and_dangling_contract_owners_are_rejected() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let key = callable_key(10, 1, None);

        let mut missing = artifact(
            &registry,
            &[(key, "crate::callable", &["crate::callable"])],
            &[key],
        );
        contract_metadata_mut(&mut missing).owner = None;
        let (_, workspace, program) = workspace_and_program(&missing, &registry, 10);
        assert!(matches!(
            WorkspaceEffectiveSafetyContracts::open(
                &workspace,
                &program,
                &ContractDocOverrides::default()
            ),
            Err(WorkspaceEffectiveSafetyContractsError::MissingOwner { .. })
        ));

        let valid = artifact(
            &registry,
            &[(key, "crate::callable", &["crate::callable"])],
            &[key],
        );
        let (scope, workspace, program) = workspace_and_program(&valid, &registry, 10);
        let mut wrong = workspace
            .artifact(&scope)
            .unwrap()
            .facts::<SafetyContractFact>()
            .unwrap()
            .pop()
            .unwrap();
        wrong.metadata.owner.as_mut().unwrap().schema =
            crate::analysis::facts::schema::SchemaId::new(SafetyContractFact::ID).unwrap();
        assert!(matches!(
            index_contract(&workspace, &program, &scope, wrong, &mut BTreeMap::new()),
            Err(WorkspaceEffectiveSafetyContractsError::InvalidOwner { .. })
        ));

        let mut dangling = workspace
            .artifact(&scope)
            .unwrap()
            .facts::<SafetyContractFact>()
            .unwrap()
            .pop()
            .unwrap();
        dangling.metadata.owner.as_mut().unwrap().row = u32::MAX;
        assert!(matches!(
            index_contract(&workspace, &program, &scope, dangling, &mut BTreeMap::new()),
            Err(WorkspaceEffectiveSafetyContractsError::InvalidOwner { .. })
        ));
    }

    #[test]
    fn duplicate_raw_contracts_for_one_callable_are_rejected() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let key = callable_key(11, 1, None);
        let artifact = artifact(
            &registry,
            &[(key, "crate::callable", &["crate::callable"])],
            &[key, key],
        );
        let (_, workspace, program) = workspace_and_program(&artifact, &registry, 11);

        assert!(matches!(
            WorkspaceEffectiveSafetyContracts::open(
                &workspace,
                &program,
                &ContractDocOverrides::default()
            ),
            Err(WorkspaceEffectiveSafetyContractsError::DuplicateOwner { .. })
        ));
    }

    #[test]
    fn reversed_input_order_produces_the_same_effective_answers() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let first = callable_key(12, 1, None);
        let second = callable_key(12, 2, None);
        let forward = artifact(
            &registry,
            &[
                (first, "crate::first", &["crate::first"]),
                (second, "crate::second", &["crate::second"]),
            ],
            &[first],
        );
        let reversed = artifact(
            &registry,
            &[
                (second, "crate::second", &["crate::second"]),
                (first, "crate::first", &["crate::first"]),
            ],
            &[first],
        );

        let answers = |artifact: &ArtifactFactIr| {
            let (scope, workspace, program) = workspace_and_program(artifact, &registry, 12);
            let contracts = WorkspaceEffectiveSafetyContracts::open(
                &workspace,
                &program,
                &ContractDocOverrides::default(),
            )
            .unwrap();
            [first, second].map(|key| {
                contracts
                    .has_effective_safety_contract(
                        &workspace,
                        &program.exact_callable(&scope, &key).unwrap().id(),
                    )
                    .unwrap()
            })
        };

        assert_eq!(answers(&forward), answers(&reversed));
    }
}
