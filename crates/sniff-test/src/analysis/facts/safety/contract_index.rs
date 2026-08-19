//! Exact-generation lookup of effective safety contract presence.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;

use super::{SafetyContractFact, SafetyRequirement};
use crate::analysis::facts::encoded::TableKind;
use crate::analysis::facts::program::topology::CallableEntity;
use crate::analysis::facts::program::workspace_index::{
    WorkspaceProgramIndex, WorkspaceProgramIndexError,
};
use crate::analysis::facts::program::{FunctionKey, SourceAnchorEntity};
use crate::analysis::facts::schema::{RowSchema, SchemaId};
use crate::analysis::facts::view::{ArtifactDbView, TypedFact, ViewError};
use crate::analysis::facts::workspace::{
    ArtifactScopeId, ScopedEntityId, ScopedEntityRef, ScopedRowRef, WorkspaceFactView,
    WorkspaceIdentity, WorkspaceViewError,
};
use crate::contracts::{
    ContractDocOverrides, normalize_requirement_name, safety_contract_doc_summary_from_markdown,
};

/// Authority lane that supplied one effective safety contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EffectiveSafetyContractOrigin {
    Override,
    RawExact,
    RawGeneric,
}

/// One source anchor already validated by the permanent program index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EffectiveSafetyContractSourceAnchor {
    id: ScopedEntityId<SourceAnchorEntity>,
    reference: ScopedEntityRef,
    data: SourceAnchorEntity,
}

impl EffectiveSafetyContractSourceAnchor {
    #[must_use]
    pub(crate) const fn id(&self) -> &ScopedEntityId<SourceAnchorEntity> {
        &self.id
    }

    #[must_use]
    pub(crate) const fn reference(&self) -> &ScopedEntityRef {
        &self.reference
    }

    #[must_use]
    pub(crate) const fn data(&self) -> &SourceAnchorEntity {
        &self.data
    }
}

/// One source-ordered effective safety requirement occurrence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EffectiveSafetyRequirement {
    ordinal: u32,
    name: String,
    normalized_name: String,
    condition: String,
    raw_requirement: Option<ScopedRowRef>,
    source_anchor: Option<EffectiveSafetyContractSourceAnchor>,
}

#[allow(
    dead_code,
    reason = "typed safety evaluation consumes the remaining requirement accessors next"
)]
impl EffectiveSafetyRequirement {
    #[must_use]
    pub(crate) const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    #[must_use]
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub(crate) fn normalized_name(&self) -> &str {
        &self.normalized_name
    }

    #[must_use]
    pub(crate) fn condition(&self) -> &str {
        &self.condition
    }

    #[must_use]
    pub(crate) const fn raw_requirement(&self) -> Option<&ScopedRowRef> {
        self.raw_requirement.as_ref()
    }

    #[must_use]
    pub(crate) const fn source_anchor(&self) -> Option<&EffectiveSafetyContractSourceAnchor> {
        self.source_anchor.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EffectiveSafetyRequirementGroup {
    normalized_name: String,
    requirements: Arc<[EffectiveSafetyRequirement]>,
}

impl EffectiveSafetyRequirementGroup {
    #[must_use]
    pub(crate) fn normalized_name(&self) -> &str {
        &self.normalized_name
    }

    #[must_use]
    pub(crate) fn requirements(&self) -> &[EffectiveSafetyRequirement] {
        &self.requirements
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EffectiveSafetyContractContent {
    requirements: Arc<[EffectiveSafetyRequirement]>,
    requirements_by_normalized_name: BTreeMap<String, Arc<[EffectiveSafetyRequirement]>>,
    duplicate_requirement_groups: Arc<[EffectiveSafetyRequirementGroup]>,
}

impl EffectiveSafetyContractContent {
    fn new(requirements: Vec<EffectiveSafetyRequirement>) -> Self {
        let mut grouped = BTreeMap::<String, Vec<EffectiveSafetyRequirement>>::new();
        for requirement in &requirements {
            grouped
                .entry(requirement.normalized_name.clone())
                .or_default()
                .push(requirement.clone());
        }
        let requirements_by_normalized_name: BTreeMap<String, Arc<[EffectiveSafetyRequirement]>> =
            grouped
                .into_iter()
                .map(|(name, requirements)| (name, Arc::from(requirements)))
                .collect::<BTreeMap<_, _>>();
        let duplicate_requirement_groups = requirements_by_normalized_name
            .iter()
            .filter(|(_, requirements)| requirements.len() > 1)
            .map(
                |(normalized_name, requirements)| EffectiveSafetyRequirementGroup {
                    normalized_name: normalized_name.clone(),
                    requirements: Arc::clone(requirements),
                },
            )
            .collect::<Vec<_>>();
        Self {
            requirements: Arc::from(requirements),
            requirements_by_normalized_name,
            duplicate_requirement_groups: Arc::from(duplicate_requirement_groups),
        }
    }
}

/// Complete effective safety contract selected for one exact queried callable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EffectiveSafetyContract {
    queried_callable: ScopedEntityId<CallableEntity>,
    declaration_owner: ScopedEntityId<CallableEntity>,
    raw_contract: Option<ScopedRowRef>,
    origin: EffectiveSafetyContractOrigin,
    source_anchor: Option<EffectiveSafetyContractSourceAnchor>,
    content: Arc<EffectiveSafetyContractContent>,
}

#[allow(
    dead_code,
    reason = "typed safety traversal consumes complete contracts in the next slice"
)]
impl EffectiveSafetyContract {
    #[must_use]
    pub(crate) const fn queried_callable(&self) -> &ScopedEntityId<CallableEntity> {
        &self.queried_callable
    }

    #[must_use]
    pub(crate) const fn declaration_owner(&self) -> &ScopedEntityId<CallableEntity> {
        &self.declaration_owner
    }

    #[must_use]
    pub(crate) const fn raw_contract(&self) -> Option<&ScopedRowRef> {
        self.raw_contract.as_ref()
    }

    #[must_use]
    pub(crate) const fn origin(&self) -> EffectiveSafetyContractOrigin {
        self.origin
    }

    #[must_use]
    pub(crate) const fn source_anchor(&self) -> Option<&EffectiveSafetyContractSourceAnchor> {
        self.source_anchor.as_ref()
    }

    #[must_use]
    pub(crate) fn requirements(&self) -> &[EffectiveSafetyRequirement] {
        &self.content.requirements
    }

    #[must_use]
    pub(crate) fn requirements_by_normalized_name(
        &self,
        normalized_name: &str,
    ) -> &[EffectiveSafetyRequirement] {
        self.content
            .requirements_by_normalized_name
            .get(normalized_name)
            .map_or(&[], AsRef::as_ref)
    }

    #[must_use]
    pub(crate) fn duplicate_requirement_groups(&self) -> &[EffectiveSafetyRequirementGroup] {
        &self.content.duplicate_requirement_groups
    }
}

#[derive(Clone, Debug)]
struct PreparedRawSafetyContract {
    declaration_owner: ScopedEntityId<CallableEntity>,
    raw_contract: ScopedRowRef,
    source_anchor: Option<EffectiveSafetyContractSourceAnchor>,
    content: Arc<EffectiveSafetyContractContent>,
}

#[derive(Clone, Debug)]
struct PreparedSafetyRequirementRow {
    owner: FunctionKey,
    requirement: EffectiveSafetyRequirement,
}

#[derive(Clone, Debug)]
struct CallableContractLookup {
    namespace_candidates: Vec<String>,
    generic: Option<ScopedEntityId<CallableEntity>>,
}

/// Immutable effective-contract lookup prepared for one exact workspace view.
#[derive(Clone, Debug)]
pub(crate) struct WorkspaceEffectiveSafetyContracts {
    workspace: Arc<WorkspaceIdentity>,
    overrides: ContractDocOverrides,
    prepared_overrides: BTreeMap<String, Option<Arc<EffectiveSafetyContractContent>>>,
    callables: BTreeMap<ScopedEntityId<CallableEntity>, CallableContractLookup>,
    raw_by_callable: BTreeMap<ScopedEntityId<CallableEntity>, Arc<PreparedRawSafetyContract>>,
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
        let prepared_overrides = prepare_overrides(overrides)?;
        let mut callables = BTreeMap::new();
        let mut raw_by_callable = BTreeMap::new();
        for scope in workspace.scopes() {
            let view = workspace
                .artifact(scope)
                .map_err(WorkspaceEffectiveSafetyContractsError::workspace)?;
            require_table::<SafetyContractFact>(scope, view, TableKind::Fact)?;
            require_table::<SafetyRequirement>(scope, view, TableKind::Requirement)?;
            for callable in view.indexed_rows::<CallableEntity>().map_err(|source| {
                WorkspaceEffectiveSafetyContractsError::ReadCallables {
                    scope: scope.clone(),
                    source: Box::new(source),
                }
            })? {
                let indexed = program
                    .exact_callable(scope, callable.data.key())
                    .ok_or_else(|| {
                        WorkspaceEffectiveSafetyContractsError::CallableNotIndexedAtOpen {
                            scope: scope.clone(),
                            key: *callable.data.key(),
                        }
                    })?;
                let generic = callable.data.key().instance().and_then(|_| {
                    program
                        .exact_callable(
                            scope,
                            &FunctionKey::new(callable.data.key().definition(), None),
                        )
                        .map(crate::analysis::facts::program::workspace_index::ScopedProgramEntity::id)
                });
                if callables
                    .insert(
                        indexed.id(),
                        CallableContractLookup {
                            namespace_candidates: callable.data.namespace_candidates().to_vec(),
                            generic,
                        },
                    )
                    .is_some()
                {
                    return Err(
                        WorkspaceEffectiveSafetyContractsError::DuplicateCallableAtOpen {
                            callable: Box::new(indexed.id()),
                        },
                    );
                }
            }
            let requirement_rows = prepare_requirement_table(program, scope, view)?;
            let contracts = view.facts::<SafetyContractFact>().map_err(|source| {
                WorkspaceEffectiveSafetyContractsError::ReadContracts {
                    scope: scope.clone(),
                    source: Box::new(source),
                }
            })?;
            validate_no_shared_requirement_refs(scope, &contracts)?;
            let mut claimed_requirements = BTreeSet::new();
            for contract in contracts {
                index_contract(
                    workspace,
                    program,
                    scope,
                    contract,
                    &requirement_rows,
                    &mut raw_by_callable,
                    &mut claimed_requirements,
                )?;
            }
            validate_requirement_coverage(scope, &requirement_rows, &claimed_requirements)?;
        }
        Ok(Self {
            workspace: workspace.identity(),
            overrides: overrides.clone(),
            prepared_overrides,
            callables,
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
        self.effective_safety_contract(workspace, callable)
            .map(|contract| contract.is_some())
    }

    pub(crate) fn effective_safety_contract(
        &self,
        workspace: &WorkspaceFactView<'_>,
        callable: &ScopedEntityId<CallableEntity>,
    ) -> Result<Option<Arc<EffectiveSafetyContract>>, WorkspaceEffectiveSafetyContractsError> {
        self.validate_workspace(workspace)?;
        let lookup = self.callables.get(callable).ok_or_else(|| {
            WorkspaceEffectiveSafetyContractsError::InvalidCallableIdentity {
                callable: Box::new(callable.erase()),
            }
        })?;
        if let Some(pattern) = self
            .overrides
            .best_pattern_for_candidates(&lookup.namespace_candidates)
        {
            let prepared = self.prepared_overrides.get(pattern).ok_or_else(|| {
                WorkspaceEffectiveSafetyContractsError::MissingPreparedOverride {
                    pattern: pattern.to_owned(),
                }
            })?;
            return Ok(prepared.as_ref().map(|content| {
                Arc::new(EffectiveSafetyContract {
                    queried_callable: callable.clone(),
                    declaration_owner: callable.clone(),
                    raw_contract: None,
                    origin: EffectiveSafetyContractOrigin::Override,
                    source_anchor: None,
                    content: Arc::clone(content),
                })
            }));
        }
        if let Some(raw) = self.raw_by_callable.get(callable) {
            return Ok(Some(materialize_raw_contract(
                callable,
                raw,
                EffectiveSafetyContractOrigin::RawExact,
            )));
        }
        Ok(lookup
            .generic
            .as_ref()
            .and_then(|generic| self.raw_by_callable.get(generic))
            .map(|raw| {
                materialize_raw_contract(callable, raw, EffectiveSafetyContractOrigin::RawGeneric)
            }))
    }
}

fn materialize_raw_contract(
    queried_callable: &ScopedEntityId<CallableEntity>,
    raw: &PreparedRawSafetyContract,
    origin: EffectiveSafetyContractOrigin,
) -> Arc<EffectiveSafetyContract> {
    Arc::new(EffectiveSafetyContract {
        queried_callable: queried_callable.clone(),
        declaration_owner: raw.declaration_owner.clone(),
        raw_contract: Some(raw.raw_contract.clone()),
        origin,
        source_anchor: raw.source_anchor.clone(),
        content: Arc::clone(&raw.content),
    })
}

fn prepare_overrides(
    overrides: &ContractDocOverrides,
) -> Result<
    BTreeMap<String, Option<Arc<EffectiveSafetyContractContent>>>,
    WorkspaceEffectiveSafetyContractsError,
> {
    let mut prepared = BTreeMap::new();
    for (pattern, markdown) in overrides.prepared_entries() {
        let summary = safety_contract_doc_summary_from_markdown(markdown);
        let value = if summary.has_docs {
            let mut requirements = Vec::with_capacity(summary.requirements.len());
            for (ordinal, requirement) in summary.requirements.into_iter().enumerate() {
                let ordinal = u32::try_from(ordinal).map_err(|_| {
                    WorkspaceEffectiveSafetyContractsError::OverrideRequirementOrdinalOverflow {
                        pattern: pattern.to_owned(),
                    }
                })?;
                requirements.push(EffectiveSafetyRequirement {
                    ordinal,
                    normalized_name: normalize_requirement_name(&requirement.name),
                    name: requirement.name,
                    condition: requirement.condition,
                    raw_requirement: None,
                    source_anchor: None,
                });
            }
            Some(Arc::new(EffectiveSafetyContractContent::new(requirements)))
        } else {
            None
        };
        prepared.entry(pattern.to_owned()).or_insert(value);
    }
    Ok(prepared)
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
    requirement_rows: &BTreeMap<ScopedRowRef, PreparedSafetyRequirementRow>,
    raw_by_callable: &mut BTreeMap<ScopedEntityId<CallableEntity>, Arc<PreparedRawSafetyContract>>,
    claimed_requirements: &mut BTreeSet<ScopedRowRef>,
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
            first: first.raw_contract.clone(),
            duplicate: source,
        });
    }
    let requirements = prepare_raw_requirements(
        scope,
        &owner,
        callable.key(),
        &source,
        &contract.metadata.requirements,
        requirement_rows,
    )?;
    let source_anchor = validate_contract_anchor(
        workspace,
        program,
        scope,
        contract.metadata.anchor.as_ref(),
        &source,
    )?;
    let prepared = Arc::new(PreparedRawSafetyContract {
        declaration_owner: owner.clone(),
        raw_contract: source,
        source_anchor,
        content: Arc::new(EffectiveSafetyContractContent::new(requirements)),
    });
    for requirement in prepared.content.requirements.iter() {
        if let Some(reference) = requirement.raw_requirement() {
            claimed_requirements.insert(reference.clone());
        }
    }
    raw_by_callable.insert(owner.clone(), prepared);
    Ok(())
}

fn prepare_raw_requirements(
    scope: &ArtifactScopeId,
    owner: &ScopedEntityId<CallableEntity>,
    owner_key: &FunctionKey,
    contract: &ScopedRowRef,
    references: &[crate::analysis::facts::encoded::RowRef],
    requirement_rows: &BTreeMap<ScopedRowRef, PreparedSafetyRequirementRow>,
) -> Result<Vec<EffectiveSafetyRequirement>, WorkspaceEffectiveSafetyContractsError> {
    let mut requirements = Vec::with_capacity(references.len());
    for reference in references {
        let scoped = ScopedRowRef::new(scope.clone(), reference.clone());
        if reference.schema.as_str() != SafetyRequirement::ID {
            return Err(
                WorkspaceEffectiveSafetyContractsError::InvalidRequirementSchema {
                    contract: contract.clone(),
                    requirement: scoped,
                },
            );
        }
        let row = requirement_rows.get(&scoped).ok_or_else(|| {
            WorkspaceEffectiveSafetyContractsError::InvalidRequirementReference {
                contract: contract.clone(),
                requirement: scoped.clone(),
            }
        })?;
        if &row.owner != owner_key {
            return Err(
                WorkspaceEffectiveSafetyContractsError::RequirementOwnerMismatch {
                    contract: Box::new(contract.clone()),
                    requirement: Box::new(scoped),
                    owner: Box::new(owner.clone()),
                },
            );
        }
        requirements.push((row.requirement.ordinal, scoped, row.requirement.clone()));
    }
    requirements.sort_by(|left, right| (left.0, &left.1).cmp(&(right.0, &right.1)));
    for (expected, (ordinal, requirement, _)) in requirements.iter().enumerate() {
        let expected = u32::try_from(expected)
            .map_err(|_| WorkspaceEffectiveSafetyContractsError::RequirementOrdinalOverflow)?;
        if *ordinal != expected {
            return Err(
                WorkspaceEffectiveSafetyContractsError::InvalidRequirementOrdinal {
                    contract: contract.clone(),
                    requirement: requirement.clone(),
                    expected,
                    found: *ordinal,
                },
            );
        }
    }
    Ok(requirements
        .into_iter()
        .map(|(_, _, requirement)| requirement)
        .collect())
}

fn prepare_requirement_table(
    program: &WorkspaceProgramIndex,
    scope: &ArtifactScopeId,
    view: ArtifactDbView<'_>,
) -> Result<
    BTreeMap<ScopedRowRef, PreparedSafetyRequirementRow>,
    WorkspaceEffectiveSafetyContractsError,
> {
    let rows = view.indexed_rows::<SafetyRequirement>().map_err(|source| {
        WorkspaceEffectiveSafetyContractsError::ReadRequirements {
            scope: scope.clone(),
            source: Box::new(source),
        }
    })?;
    let mut prepared = BTreeMap::new();
    for row in rows {
        let reference = ScopedRowRef::new(scope.clone(), row.reference);
        if program.exact_callable(scope, row.data.owner()).is_none() {
            return Err(
                WorkspaceEffectiveSafetyContractsError::RequirementOwnerNotIndexed {
                    requirement: reference,
                    owner: *row.data.owner(),
                },
            );
        }
        let normalized_name = row.data.normalized_name();
        if normalized_name.is_empty() {
            return Err(
                WorkspaceEffectiveSafetyContractsError::EmptyRequirementName {
                    requirement: reference,
                },
            );
        }
        let owner = *row.data.owner();
        let source_anchor = row
            .data
            .source_anchor()
            .map(|key| {
                let indexed = program.exact_source_anchor(scope, key).ok_or_else(|| {
                    WorkspaceEffectiveSafetyContractsError::RequirementAnchorNotIndexed {
                        requirement: reference.clone(),
                        key: Box::new(key.clone()),
                    }
                })?;
                Ok(EffectiveSafetyContractSourceAnchor {
                    id: indexed.id(),
                    reference: indexed.reference().clone(),
                    data: indexed.data().clone(),
                })
            })
            .transpose()?;
        let requirement = EffectiveSafetyRequirement {
            ordinal: row.data.ordinal(),
            name: row.data.name().to_owned(),
            normalized_name,
            condition: row.data.condition().to_owned(),
            raw_requirement: Some(reference.clone()),
            source_anchor,
        };
        if prepared
            .insert(
                reference.clone(),
                PreparedSafetyRequirementRow { owner, requirement },
            )
            .is_some()
        {
            return Err(
                WorkspaceEffectiveSafetyContractsError::DuplicateRequirementRow {
                    requirement: reference,
                },
            );
        }
    }
    Ok(prepared)
}

fn validate_contract_anchor(
    workspace: &WorkspaceFactView<'_>,
    program: &WorkspaceProgramIndex,
    scope: &ArtifactScopeId,
    anchor: Option<&crate::analysis::facts::encoded::EntityRef>,
    contract: &ScopedRowRef,
) -> Result<Option<EffectiveSafetyContractSourceAnchor>, WorkspaceEffectiveSafetyContractsError> {
    let Some(anchor) = anchor else {
        return Ok(None);
    };
    let reference = ScopedEntityRef::new(scope.clone(), anchor.clone());
    let data = workspace
        .entity::<SourceAnchorEntity>(&reference)
        .map_err(
            |source| WorkspaceEffectiveSafetyContractsError::InvalidContractAnchor {
                contract: contract.clone(),
                anchor: Box::new(reference.clone()),
                source: Box::new(source),
            },
        )?;
    let indexed = program
        .exact_source_anchor(scope, data.anchor())
        .filter(|indexed| indexed.reference() == &reference)
        .ok_or_else(
            || WorkspaceEffectiveSafetyContractsError::ContractAnchorNotIndexed {
                contract: contract.clone(),
                anchor: Box::new(reference),
            },
        )?;
    Ok(Some(EffectiveSafetyContractSourceAnchor {
        id: indexed.id(),
        reference: indexed.reference().clone(),
        data: indexed.data().clone(),
    }))
}

fn validate_requirement_coverage(
    scope: &ArtifactScopeId,
    all: &BTreeMap<ScopedRowRef, PreparedSafetyRequirementRow>,
    referenced: &BTreeSet<ScopedRowRef>,
) -> Result<(), WorkspaceEffectiveSafetyContractsError> {
    for requirement in all.keys() {
        if !referenced.contains(requirement) {
            return Err(WorkspaceEffectiveSafetyContractsError::OrphanRequirement {
                scope: scope.clone(),
                requirement: requirement.clone(),
            });
        }
    }
    Ok(())
}

fn validate_no_shared_requirement_refs(
    scope: &ArtifactScopeId,
    contracts: &[TypedFact<SafetyContractFact>],
) -> Result<(), WorkspaceEffectiveSafetyContractsError> {
    let mut claims = BTreeSet::new();
    for contract in contracts {
        for reference in &contract.metadata.requirements {
            if reference.schema.as_str() != SafetyRequirement::ID {
                continue;
            }
            let requirement = ScopedRowRef::new(scope.clone(), reference.clone());
            if !claims.insert(requirement.clone()) {
                return Err(WorkspaceEffectiveSafetyContractsError::SharedRequirement {
                    scope: scope.clone(),
                    requirement,
                });
            }
        }
    }
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
    ReadCallables {
        scope: ArtifactScopeId,
        source: Box<ViewError>,
    },
    ReadRequirements {
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
    CallableNotIndexedAtOpen {
        scope: ArtifactScopeId,
        key: FunctionKey,
    },
    DuplicateCallableAtOpen {
        callable: Box<ScopedEntityId<CallableEntity>>,
    },
    MissingPreparedOverride {
        pattern: String,
    },
    OverrideRequirementOrdinalOverflow {
        pattern: String,
    },
    InvalidRequirementSchema {
        contract: ScopedRowRef,
        requirement: ScopedRowRef,
    },
    InvalidRequirementReference {
        contract: ScopedRowRef,
        requirement: ScopedRowRef,
    },
    RequirementOwnerNotIndexed {
        requirement: ScopedRowRef,
        owner: FunctionKey,
    },
    RequirementOwnerMismatch {
        contract: Box<ScopedRowRef>,
        requirement: Box<ScopedRowRef>,
        owner: Box<ScopedEntityId<CallableEntity>>,
    },
    RequirementAnchorNotIndexed {
        requirement: ScopedRowRef,
        key: Box<crate::analysis::facts::program::SourceAnchorKey>,
    },
    InvalidContractAnchor {
        contract: ScopedRowRef,
        anchor: Box<ScopedEntityRef>,
        source: Box<WorkspaceViewError>,
    },
    ContractAnchorNotIndexed {
        contract: ScopedRowRef,
        anchor: Box<ScopedEntityRef>,
    },
    EmptyRequirementName {
        requirement: ScopedRowRef,
    },
    RequirementOrdinalOverflow,
    InvalidRequirementOrdinal {
        contract: ScopedRowRef,
        requirement: ScopedRowRef,
        expected: u32,
        found: u32,
    },
    DuplicateRequirementRow {
        requirement: ScopedRowRef,
    },
    SharedRequirement {
        scope: ArtifactScopeId,
        requirement: ScopedRowRef,
    },
    OrphanRequirement {
        scope: ArtifactScopeId,
        requirement: ScopedRowRef,
    },
    InvalidCallableIdentity {
        callable: Box<ScopedEntityRef>,
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

#[allow(
    clippy::too_many_lines,
    reason = "the exhaustive formatter preserves one precise message per integrity failure"
)]
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
            Self::ReadCallables { scope, .. } => write!(
                formatter,
                "cannot read callable identities in artifact scope `{scope}`"
            ),
            Self::ReadRequirements { scope, .. } => write!(
                formatter,
                "cannot read safety requirements in artifact scope `{scope}`"
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
            Self::CallableNotIndexedAtOpen { scope, key } => write!(
                formatter,
                "callable {key:?} in artifact scope `{scope}` is absent from the permanent program index"
            ),
            Self::DuplicateCallableAtOpen { callable } => write!(
                formatter,
                "callable identity {callable:?} appears more than once while preparing safety contracts"
            ),
            Self::MissingPreparedOverride { pattern } => write!(
                formatter,
                "selected safety contract override `{pattern}` was not prepared"
            ),
            Self::OverrideRequirementOrdinalOverflow { pattern } => write!(
                formatter,
                "safety contract override `{pattern}` declares too many requirements"
            ),
            Self::InvalidRequirementSchema {
                contract,
                requirement,
            } => write!(
                formatter,
                "safety contract {contract:?} references non-safety requirement {requirement:?}"
            ),
            Self::InvalidRequirementReference {
                contract,
                requirement,
            } => write!(
                formatter,
                "safety contract {contract:?} references unavailable requirement {requirement:?}"
            ),
            Self::RequirementOwnerNotIndexed { requirement, owner } => write!(
                formatter,
                "safety requirement {requirement:?} owner {owner:?} is absent from the permanent program index"
            ),
            Self::RequirementOwnerMismatch {
                contract,
                requirement,
                owner,
            } => write!(
                formatter,
                "safety contract {contract:?} requirement {requirement:?} does not belong to callable {owner:?}"
            ),
            Self::RequirementAnchorNotIndexed { requirement, key } => write!(
                formatter,
                "safety requirement {requirement:?} names unindexed source anchor {key:?}"
            ),
            Self::InvalidContractAnchor {
                contract, anchor, ..
            } => write!(
                formatter,
                "safety contract {contract:?} has invalid source anchor {anchor:?}"
            ),
            Self::ContractAnchorNotIndexed { contract, anchor } => write!(
                formatter,
                "safety contract {contract:?} source anchor {anchor:?} is absent from the permanent program index"
            ),
            Self::EmptyRequirementName { requirement } => write!(
                formatter,
                "safety requirement {requirement:?} has an empty normalized name"
            ),
            Self::RequirementOrdinalOverflow => {
                formatter.write_str("safety contract declares too many requirements")
            }
            Self::InvalidRequirementOrdinal {
                contract,
                requirement,
                expected,
                found,
            } => write!(
                formatter,
                "safety contract {contract:?} requirement {requirement:?} has ordinal {found}, expected {expected}"
            ),
            Self::DuplicateRequirementRow { requirement } => write!(
                formatter,
                "safety requirement {requirement:?} appears more than once while preparing contracts"
            ),
            Self::SharedRequirement { scope, requirement } => write!(
                formatter,
                "artifact scope `{scope}` lets multiple safety contracts claim requirement {requirement:?}"
            ),
            Self::OrphanRequirement { scope, requirement } => write!(
                formatter,
                "artifact scope `{scope}` contains unclaimed safety requirement {requirement:?}"
            ),
            Self::InvalidCallableIdentity { callable } => {
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
            | Self::InvalidContractAnchor { source, .. } => Some(source.as_ref()),
            Self::ReadContracts { source, .. }
            | Self::ReadCallables { source, .. }
            | Self::ReadRequirements { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::super::{SafetyContractFact, SafetyRequirement};
    use super::{
        EffectiveSafetyContractOrigin, WorkspaceEffectiveSafetyContracts,
        WorkspaceEffectiveSafetyContractsError, index_contract,
        validate_no_shared_requirement_refs,
    };
    use crate::analysis::facts::builder::{ArtifactDbBuilder, FactMeta};
    use crate::analysis::facts::collection::CollectedArtifactSchemaPack;
    use crate::analysis::facts::encoded::ArtifactFactIr;
    use crate::analysis::facts::pack::AnalysisRegistry;
    use crate::analysis::facts::program::topology::CallableEntity;
    use crate::analysis::facts::program::workspace_index::{
        VerifiedArtifactOwner, WorkspaceProgramIndex,
    };
    use crate::analysis::facts::program::{
        FunctionKey, SourceAnchorEntity, SourceAnchorInFile, SourceAnchorKey, SourceFileEntity,
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

    fn artifact_with_requirements(
        registry: &AnalysisRegistry<()>,
        owner: FunctionKey,
        requirements: &[SafetyRequirement],
    ) -> ArtifactFactIr {
        let mut builder = ArtifactDbBuilder::new();
        for descriptor in registry.schemas().descriptors() {
            builder.declare_table(descriptor).unwrap();
        }
        let callable = builder
            .insert_entity(&CallableEntity::new(
                owner,
                "crate::callable",
                false,
                false,
                false,
                false,
                vec![String::from("crate::callable")],
            ))
            .unwrap();
        let mut metadata = FactMeta::new(PassId::new("test.safety.contract-index").unwrap())
            .with_owner(&callable)
            .unwrap();
        for requirement in requirements {
            let handle = builder.insert_requirement(requirement).unwrap();
            metadata = metadata.with_requirement(&handle).unwrap();
        }
        builder
            .insert_fact(&SafetyContractFact::new(), metadata)
            .unwrap();
        builder.finalize(registry.schemas()).unwrap()
    }

    fn artifact_with_anchored_contract_and_requirement(
        registry: &AnalysisRegistry<()>,
        owner: FunctionKey,
    ) -> ArtifactFactIr {
        let mut builder = ArtifactDbBuilder::new();
        for descriptor in registry.schemas().descriptors() {
            builder.declare_table(descriptor).unwrap();
        }
        let callable = builder
            .insert_entity(&CallableEntity::new(
                owner,
                "crate::callable",
                false,
                false,
                false,
                false,
                vec![String::from("crate::callable")],
            ))
            .unwrap();
        let file = builder
            .insert_entity(&SourceFileEntity::new(
                "src/lib.rs",
                "src/lib.rs",
                "verified",
                100,
            ))
            .unwrap();
        let contract_key = SourceAnchorKey::new("src/lib.rs", 10, 20);
        let requirement_key = SourceAnchorKey::new("src/lib.rs", 30, 40);
        let contract_anchor = builder
            .insert_entity(&SourceAnchorEntity::new(contract_key.clone()))
            .unwrap();
        let requirement_anchor = builder
            .insert_entity(&SourceAnchorEntity::new(requirement_key.clone()))
            .unwrap();
        builder
            .relate(&contract_anchor, &file, &SourceAnchorInFile::new())
            .unwrap();
        builder
            .relate(&requirement_anchor, &file, &SourceAnchorInFile::new())
            .unwrap();
        let requirement = builder
            .insert_requirement(&SafetyRequirement::new(
                owner,
                0,
                "ready",
                "ready condition",
                Some(requirement_key),
            ))
            .unwrap();
        let metadata = FactMeta::new(PassId::new("test.safety.contract-index").unwrap())
            .with_owner(&callable)
            .unwrap()
            .with_anchor(&contract_anchor)
            .unwrap()
            .with_requirement(&requirement)
            .unwrap();
        builder
            .insert_fact(&SafetyContractFact::new(), metadata)
            .unwrap();
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

    fn safety_requirement_table_mut(
        artifact: &mut ArtifactFactIr,
    ) -> &mut crate::analysis::facts::encoded::EncodedTable {
        artifact
            .tables
            .iter_mut()
            .find(|table| table.schema.as_str() == SafetyRequirement::ID)
            .expect("fixture contains the safety requirement table")
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
        let contract = contracts
            .effective_safety_contract(&workspace, &exact)
            .unwrap()
            .unwrap();
        assert_eq!(contract.origin(), EffectiveSafetyContractOrigin::RawGeneric);
        assert_eq!(contract.queried_callable(), &exact);
        assert_eq!(contract.declaration_owner(), &generic);
    }

    #[test]
    fn complete_raw_contract_preserves_requirement_order_and_origin() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let owner = callable_key(13, 1, None);
        let artifact = artifact_with_requirements(
            &registry,
            owner,
            &[
                SafetyRequirement::new(owner, 0, "initialized", "the value is initialized", None),
                SafetyRequirement::new(owner, 1, "aligned", "the pointer is aligned", None),
            ],
        );
        let (scope, workspace, program) = workspace_and_program(&artifact, &registry, 13);
        let contracts = WorkspaceEffectiveSafetyContracts::open(
            &workspace,
            &program,
            &ContractDocOverrides::default(),
        )
        .unwrap();
        let callable = program.exact_callable(&scope, &owner).unwrap().id();

        let contract = contracts
            .effective_safety_contract(&workspace, &callable)
            .unwrap()
            .expect("the raw contract is effective");

        assert_eq!(contract.origin(), EffectiveSafetyContractOrigin::RawExact);
        assert_eq!(contract.queried_callable(), &callable);
        assert_eq!(contract.declaration_owner(), &callable);
        assert!(contract.raw_contract().is_some());
        assert_eq!(
            contract
                .requirements()
                .iter()
                .map(|requirement| (requirement.ordinal(), requirement.name()))
                .collect::<Vec<_>>(),
            vec![(0, "initialized"), (1, "aligned")]
        );
    }

    #[test]
    fn effective_contract_groups_duplicate_normalized_requirements() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let owner = callable_key(14, 1, None);
        let artifact = artifact_with_requirements(
            &registry,
            owner,
            &[
                SafetyRequirement::new(owner, 0, "Initialized", "first", None),
                SafetyRequirement::new(owner, 1, " initialized ", "second", None),
            ],
        );
        let (scope, workspace, program) = workspace_and_program(&artifact, &registry, 14);
        let contracts = WorkspaceEffectiveSafetyContracts::open(
            &workspace,
            &program,
            &ContractDocOverrides::default(),
        )
        .unwrap();
        let callable = program.exact_callable(&scope, &owner).unwrap().id();
        let contract = contracts
            .effective_safety_contract(&workspace, &callable)
            .unwrap()
            .unwrap();

        assert_eq!(
            contract.requirements_by_normalized_name("initialized"),
            contract.requirements()
        );
        let [duplicate] = contract.duplicate_requirement_groups() else {
            panic!("one duplicate normalized-name group must be retained");
        };
        assert_eq!(duplicate.normalized_name(), "initialized");
        assert_eq!(duplicate.requirements(), contract.requirements());
    }

    #[test]
    fn complete_raw_contract_retains_verified_source_anchors() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let owner = callable_key(15, 1, None);
        let artifact = artifact_with_anchored_contract_and_requirement(&registry, owner);
        let (scope, workspace, program) = workspace_and_program(&artifact, &registry, 15);
        let contracts = WorkspaceEffectiveSafetyContracts::open(
            &workspace,
            &program,
            &ContractDocOverrides::default(),
        )
        .unwrap();
        let callable = program.exact_callable(&scope, &owner).unwrap().id();
        let contract = contracts
            .effective_safety_contract(&workspace, &callable)
            .unwrap()
            .unwrap();

        assert_eq!(
            contract.source_anchor().unwrap().data().anchor(),
            &SourceAnchorKey::new("src/lib.rs", 10, 20)
        );
        assert_eq!(
            contract.requirements()[0]
                .source_anchor()
                .unwrap()
                .data()
                .anchor(),
            &SourceAnchorKey::new("src/lib.rs", 30, 40)
        );
    }

    #[test]
    fn orphan_and_shared_requirement_rows_are_rejected() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let owner = callable_key(16, 1, None);
        let requirement = SafetyRequirement::new(owner, 0, "ready", "condition", None);

        let mut orphan = artifact_with_requirements(&registry, owner, &[requirement.clone()]);
        contract_metadata_mut(&mut orphan).requirements.clear();
        let (_, workspace, program) = workspace_and_program(&orphan, &registry, 16);
        assert!(matches!(
            WorkspaceEffectiveSafetyContracts::open(
                &workspace,
                &program,
                &ContractDocOverrides::default(),
            ),
            Err(WorkspaceEffectiveSafetyContractsError::OrphanRequirement { .. })
        ));

        let shared = artifact_with_requirements(&registry, owner, &[requirement]);
        let scope = ArtifactScopeId::for_in_memory(16, 0);
        let view = ArtifactDbView::open(&shared, registry.schemas()).unwrap();
        let contract = view.facts::<SafetyContractFact>().unwrap().pop().unwrap();
        assert!(matches!(
            validate_no_shared_requirement_refs(&scope, &[contract.clone(), contract]),
            Err(WorkspaceEffectiveSafetyContractsError::SharedRequirement { .. })
        ));

        let mut malformed_orphan = orphan;
        safety_requirement_table_mut(&mut malformed_orphan).rows[0].data["name"] =
            serde_json::json!("---");
        let (_, workspace, program) = workspace_and_program(&malformed_orphan, &registry, 16);
        assert!(matches!(
            WorkspaceEffectiveSafetyContracts::open(
                &workspace,
                &program,
                &ContractDocOverrides::default(),
            ),
            Err(WorkspaceEffectiveSafetyContractsError::EmptyRequirementName { .. })
        ));
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
    fn override_retains_complete_requirement_content_without_raw_identities() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let callable = callable_key(17, 1, None);
        let artifact = artifact(
            &registry,
            &[(callable, "dependency::run", &["dependency::run"])],
            &[],
        );
        let (scope, workspace, program) = workspace_and_program(&artifact, &registry, 17);
        let overrides = ContractDocOverrides::new(vec![(
            String::from("dependency::run"),
            String::from("# Safety\n- aligned: the pointer is aligned"),
        )])
        .unwrap();
        let contracts =
            WorkspaceEffectiveSafetyContracts::open(&workspace, &program, &overrides).unwrap();
        drop(overrides);
        let callable = program.exact_callable(&scope, &callable).unwrap().id();

        let contract = contracts
            .effective_safety_contract(&workspace, &callable)
            .unwrap()
            .unwrap();
        assert_eq!(contract.origin(), EffectiveSafetyContractOrigin::Override);
        assert!(contract.raw_contract().is_none());
        assert!(contract.source_anchor().is_none());
        assert_eq!(contract.requirements()[0].name(), "aligned");
        assert_eq!(
            contract.requirements()[0].condition(),
            "the pointer is aligned"
        );
        assert!(contract.requirements()[0].raw_requirement().is_none());
        assert!(contract.requirements()[0].source_anchor().is_none());
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
            index_contract(
                &workspace,
                &program,
                &scope,
                wrong,
                &BTreeMap::new(),
                &mut BTreeMap::new(),
                &mut BTreeSet::new(),
            ),
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
            index_contract(
                &workspace,
                &program,
                &scope,
                dangling,
                &BTreeMap::new(),
                &mut BTreeMap::new(),
                &mut BTreeSet::new(),
            ),
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

    #[test]
    fn fabricated_callable_identity_is_rejected() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let key = callable_key(18, 1, None);
        let artifact = artifact(
            &registry,
            &[(key, "crate::callable", &["crate::callable"])],
            &[key],
        );
        let (scope, workspace, program) = workspace_and_program(&artifact, &registry, 18);
        let contracts = WorkspaceEffectiveSafetyContracts::open(
            &workspace,
            &program,
            &ContractDocOverrides::default(),
        )
        .unwrap();
        let valid = program.exact_callable(&scope, &key).unwrap().id();
        let fabricated = crate::analysis::facts::workspace::ScopedEntityId::new(
            scope.clone(),
            crate::analysis::facts::schema::EntityId::new(u32::MAX),
        );
        let foreign_scope = crate::analysis::facts::workspace::ScopedEntityId::new(
            ArtifactScopeId::for_in_memory(19, 0),
            valid.entity(),
        );

        for invalid in [&fabricated, &foreign_scope] {
            assert!(matches!(
                contracts.effective_safety_contract(&workspace, invalid),
                Err(WorkspaceEffectiveSafetyContractsError::InvalidCallableIdentity { .. })
            ));
        }
    }
}
