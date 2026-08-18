//! Exact-generation lookup of complete effective panic contracts.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;

use super::contracts::{PanicContractFact, PanicRequirement};
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
use crate::contracts::{ContractDocOverrides, panic_contract_doc_summary_from_markdown};

/// Authority lane that supplied one effective panic contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EffectivePanicContractOrigin {
    Override,
    RawExact,
    RawGeneric,
}

/// One exact source anchor already validated by the permanent program index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EffectivePanicContractSourceAnchor {
    id: ScopedEntityId<SourceAnchorEntity>,
    reference: ScopedEntityRef,
    data: SourceAnchorEntity,
}

impl EffectivePanicContractSourceAnchor {
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

/// One source-ordered effective panic requirement occurrence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EffectivePanicRequirement {
    ordinal: u32,
    name: String,
    normalized_name: String,
    condition: String,
    raw_requirement: Option<ScopedRowRef>,
    source_anchor: Option<EffectivePanicContractSourceAnchor>,
}

impl EffectivePanicRequirement {
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
    pub(crate) const fn source_anchor(&self) -> Option<&EffectivePanicContractSourceAnchor> {
        self.source_anchor.as_ref()
    }
}

/// Repeated normalized requirement name, retained in declaration order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EffectivePanicRequirementGroup {
    normalized_name: String,
    requirements: Arc<[EffectivePanicRequirement]>,
}

impl EffectivePanicRequirementGroup {
    #[must_use]
    pub(crate) fn normalized_name(&self) -> &str {
        &self.normalized_name
    }

    #[must_use]
    pub(crate) fn requirements(&self) -> &[EffectivePanicRequirement] {
        &self.requirements
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EffectivePanicContractContent {
    requirements: Arc<[EffectivePanicRequirement]>,
    requirements_by_normalized_name: BTreeMap<String, Arc<[EffectivePanicRequirement]>>,
    duplicate_requirement_groups: Arc<[EffectivePanicRequirementGroup]>,
}

impl EffectivePanicContractContent {
    fn new(requirements: Vec<EffectivePanicRequirement>) -> Self {
        let mut grouped = BTreeMap::<String, Vec<EffectivePanicRequirement>>::new();
        for requirement in &requirements {
            grouped
                .entry(requirement.normalized_name.clone())
                .or_default()
                .push(requirement.clone());
        }
        let grouped: BTreeMap<String, Arc<[EffectivePanicRequirement]>> = grouped
            .into_iter()
            .map(|(name, requirements)| (name, Arc::from(requirements)))
            .collect::<BTreeMap<_, _>>();

        let duplicate_requirement_groups = grouped
            .iter()
            .filter(|(_, occurrences)| occurrences.len() > 1)
            .map(
                |(normalized_name, occurrences)| EffectivePanicRequirementGroup {
                    normalized_name: normalized_name.clone(),
                    requirements: Arc::clone(occurrences),
                },
            )
            .collect::<Vec<_>>();

        Self {
            requirements: Arc::from(requirements),
            requirements_by_normalized_name: grouped,
            duplicate_requirement_groups: Arc::from(duplicate_requirement_groups),
        }
    }
}

/// Complete effective panic contract selected for one exact queried callable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EffectivePanicContract {
    queried_callable: ScopedEntityId<CallableEntity>,
    declaration_owner: ScopedEntityId<CallableEntity>,
    raw_contract: Option<ScopedRowRef>,
    origin: EffectivePanicContractOrigin,
    source_anchor: Option<EffectivePanicContractSourceAnchor>,
    content: Arc<EffectivePanicContractContent>,
}

impl EffectivePanicContract {
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
    pub(crate) const fn origin(&self) -> EffectivePanicContractOrigin {
        self.origin
    }

    #[must_use]
    pub(crate) const fn source_anchor(&self) -> Option<&EffectivePanicContractSourceAnchor> {
        self.source_anchor.as_ref()
    }

    #[must_use]
    pub(crate) fn requirements(&self) -> &[EffectivePanicRequirement] {
        &self.content.requirements
    }

    #[must_use]
    pub(crate) fn requirements_by_normalized_name(
        &self,
        normalized_name: &str,
    ) -> &[EffectivePanicRequirement] {
        self.content
            .requirements_by_normalized_name
            .get(normalized_name)
            .map_or(&[], AsRef::as_ref)
    }

    #[must_use]
    pub(crate) fn duplicate_requirement_groups(&self) -> &[EffectivePanicRequirementGroup] {
        &self.content.duplicate_requirement_groups
    }
}

#[derive(Clone, Debug)]
struct PreparedRawPanicContract {
    declaration_owner: ScopedEntityId<CallableEntity>,
    raw_contract: ScopedRowRef,
    source_anchor: Option<EffectivePanicContractSourceAnchor>,
    content: Arc<EffectivePanicContractContent>,
}

#[derive(Clone, Debug)]
struct PreparedPanicRequirementRow {
    owner: FunctionKey,
    requirement: EffectivePanicRequirement,
}

#[derive(Clone, Debug)]
struct CallableContractLookup {
    namespace_candidates: Vec<String>,
    generic: Option<ScopedEntityId<CallableEntity>>,
}

/// Immutable effective-contract lookup prepared for one exact workspace view.
#[derive(Clone, Debug)]
pub(crate) struct WorkspaceEffectivePanicContracts {
    workspace: Arc<WorkspaceIdentity>,
    overrides: ContractDocOverrides,
    prepared_overrides: BTreeMap<String, Option<Arc<EffectivePanicContractContent>>>,
    callables: BTreeMap<ScopedEntityId<CallableEntity>, CallableContractLookup>,
    raw_by_callable: BTreeMap<ScopedEntityId<CallableEntity>, Arc<PreparedRawPanicContract>>,
    #[cfg(test)]
    coverage_requirement_visits: usize,
}

impl WorkspaceEffectivePanicContracts {
    pub(crate) fn open(
        workspace: &WorkspaceFactView<'_>,
        program: &WorkspaceProgramIndex,
        overrides: &ContractDocOverrides,
    ) -> Result<Self, WorkspaceEffectivePanicContractsError> {
        program
            .validate_workspace(workspace)
            .map_err(WorkspaceEffectivePanicContractsError::program)?;
        let prepared_overrides = prepare_overrides(overrides)?;
        let mut callables = BTreeMap::new();
        let mut raw_by_callable = BTreeMap::new();
        #[cfg(test)]
        let mut coverage_requirement_visits = 0usize;
        for scope in workspace.scopes() {
            let view = workspace
                .artifact(scope)
                .map_err(WorkspaceEffectivePanicContractsError::workspace)?;
            require_table::<PanicContractFact>(scope, view, TableKind::Fact)?;
            require_table::<PanicRequirement>(scope, view, TableKind::Requirement)?;
            for callable in view.indexed_rows::<CallableEntity>().map_err(|source| {
                WorkspaceEffectivePanicContractsError::ReadCallables {
                    scope: scope.clone(),
                    source: Box::new(source),
                }
            })? {
                let indexed = program
                    .exact_callable(scope, callable.data.key())
                    .ok_or_else(|| {
                        WorkspaceEffectivePanicContractsError::CallableNotIndexedAtOpen {
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
                        WorkspaceEffectivePanicContractsError::DuplicateCallableAtOpen {
                            callable: Box::new(indexed.id()),
                        },
                    );
                }
            }
            let requirement_rows = prepare_requirement_table(program, scope, view)?;
            let contracts = view.facts::<PanicContractFact>().map_err(|source| {
                WorkspaceEffectivePanicContractsError::ReadContracts {
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
            #[cfg(test)]
            {
                let coverage_visits =
                    validate_requirement_coverage(scope, &requirement_rows, &claimed_requirements)?;
                coverage_requirement_visits =
                    coverage_requirement_visits.saturating_add(coverage_visits);
            }
            #[cfg(not(test))]
            {
                validate_requirement_coverage(scope, &requirement_rows, &claimed_requirements)?;
            }
        }
        Ok(Self {
            workspace: workspace.identity(),
            overrides: overrides.clone(),
            prepared_overrides,
            callables,
            raw_by_callable,
            #[cfg(test)]
            coverage_requirement_visits,
        })
    }

    pub(crate) fn validate_workspace(
        &self,
        workspace: &WorkspaceFactView<'_>,
    ) -> Result<(), WorkspaceEffectivePanicContractsError> {
        if workspace.has_identity(&self.workspace) {
            Ok(())
        } else {
            Err(WorkspaceEffectivePanicContractsError::WorkspaceMismatch)
        }
    }

    pub(crate) fn has_effective_panic_contract(
        &self,
        workspace: &WorkspaceFactView<'_>,
        callable: &ScopedEntityId<CallableEntity>,
    ) -> Result<bool, WorkspaceEffectivePanicContractsError> {
        self.effective_panic_contract(workspace, callable)
            .map(|contract| contract.is_some())
    }

    pub(crate) fn effective_panic_contract(
        &self,
        workspace: &WorkspaceFactView<'_>,
        callable: &ScopedEntityId<CallableEntity>,
    ) -> Result<Option<Arc<EffectivePanicContract>>, WorkspaceEffectivePanicContractsError> {
        self.validate_workspace(workspace)?;
        let lookup = self.callables.get(callable).ok_or_else(|| {
            WorkspaceEffectivePanicContractsError::InvalidCallableIdentity {
                callable: Box::new(callable.erase()),
            }
        })?;

        if let Some(pattern) = self
            .overrides
            .best_pattern_for_candidates(&lookup.namespace_candidates)
        {
            let prepared = self.prepared_overrides.get(pattern).ok_or_else(|| {
                WorkspaceEffectivePanicContractsError::MissingPreparedOverride {
                    pattern: pattern.to_owned(),
                }
            })?;
            return Ok(prepared.as_ref().map(|content| {
                Arc::new(EffectivePanicContract {
                    queried_callable: callable.clone(),
                    declaration_owner: callable.clone(),
                    raw_contract: None,
                    origin: EffectivePanicContractOrigin::Override,
                    source_anchor: None,
                    content: Arc::clone(content),
                })
            }));
        }

        if let Some(raw) = self.raw_by_callable.get(callable) {
            return Ok(Some(materialize_raw_contract(
                callable,
                raw,
                EffectivePanicContractOrigin::RawExact,
            )));
        }
        Ok(lookup
            .generic
            .as_ref()
            .and_then(|generic| self.raw_by_callable.get(generic))
            .map(|raw| {
                materialize_raw_contract(callable, raw, EffectivePanicContractOrigin::RawGeneric)
            }))
    }

    #[cfg(test)]
    const fn coverage_requirement_visits(&self) -> usize {
        self.coverage_requirement_visits
    }
}

fn materialize_raw_contract(
    queried_callable: &ScopedEntityId<CallableEntity>,
    raw: &PreparedRawPanicContract,
    origin: EffectivePanicContractOrigin,
) -> Arc<EffectivePanicContract> {
    Arc::new(EffectivePanicContract {
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
    BTreeMap<String, Option<Arc<EffectivePanicContractContent>>>,
    WorkspaceEffectivePanicContractsError,
> {
    let mut prepared = BTreeMap::new();
    for (pattern, markdown) in overrides.prepared_entries() {
        let summary = panic_contract_doc_summary_from_markdown(markdown);
        let value = if summary.has_docs {
            let mut requirements = Vec::with_capacity(summary.requirements.len());
            for (ordinal, requirement) in summary.requirements.into_iter().enumerate() {
                let ordinal = u32::try_from(ordinal).map_err(|_| {
                    WorkspaceEffectivePanicContractsError::OverrideRequirementOrdinalOverflow {
                        pattern: pattern.to_owned(),
                    }
                })?;
                requirements.push(EffectivePanicRequirement {
                    ordinal,
                    normalized_name: crate::contracts::normalize_requirement_name(
                        &requirement.name,
                    ),
                    name: requirement.name,
                    condition: requirement.condition,
                    raw_requirement: None,
                    source_anchor: None,
                });
            }
            Some(Arc::new(EffectivePanicContractContent::new(requirements)))
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
) -> Result<(), WorkspaceEffectivePanicContractsError> {
    let schema = SchemaId::new(S::ID).map_err(|source| {
        WorkspaceEffectivePanicContractsError::InvalidBuiltInSchema {
            schema: S::ID,
            reason: source.to_string(),
        }
    })?;
    let descriptor = view.registry().descriptor(&schema).ok_or_else(|| {
        WorkspaceEffectivePanicContractsError::SchemaUnavailable {
            scope: scope.clone(),
            schema: schema.clone(),
        }
    })?;
    if descriptor.kind() != expected {
        return Err(WorkspaceEffectivePanicContractsError::InvalidTableKind {
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
        return Err(WorkspaceEffectivePanicContractsError::MissingTable {
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
    contract: TypedFact<PanicContractFact>,
    requirement_rows: &BTreeMap<ScopedRowRef, PreparedPanicRequirementRow>,
    raw_by_callable: &mut BTreeMap<ScopedEntityId<CallableEntity>, Arc<PreparedRawPanicContract>>,
    claimed_requirements: &mut BTreeSet<ScopedRowRef>,
) -> Result<(), WorkspaceEffectivePanicContractsError> {
    let source = ScopedRowRef::new(scope.clone(), contract.fact.reference);
    let owner = contract
        .metadata
        .owner
        .map(|owner| ScopedEntityRef::new(scope.clone(), owner))
        .ok_or_else(|| WorkspaceEffectivePanicContractsError::MissingOwner {
            contract: source.clone(),
        })?;
    let callable = workspace
        .entity::<CallableEntity>(&owner)
        .map_err(
            |error| WorkspaceEffectivePanicContractsError::InvalidOwner {
                contract: source.clone(),
                owner: Box::new(owner.clone()),
                source: Box::new(error),
            },
        )?;
    let indexed_owner = program
        .exact_callable(scope, callable.key())
        .filter(|indexed| indexed.reference() == &owner)
        .ok_or_else(|| WorkspaceEffectivePanicContractsError::OwnerNotIndexed {
            contract: source.clone(),
            owner: Box::new(owner),
        })?;
    let owner_key = *callable.key();
    let owner = indexed_owner.id();
    if let Some(first) = raw_by_callable.get(&owner) {
        return Err(WorkspaceEffectivePanicContractsError::DuplicateOwner {
            owner: Box::new(owner),
            first: Box::new(first.raw_contract.clone()),
            duplicate: Box::new(source),
        });
    }
    let source_anchor = validate_anchor(
        workspace,
        program,
        scope,
        contract.metadata.anchor.as_ref(),
        &source,
        None,
    )?;
    let requirements = prepare_raw_requirements(
        scope,
        &owner,
        &owner_key,
        &source,
        &contract.metadata.requirements,
        requirement_rows,
    )?;
    let prepared = Arc::new(PreparedRawPanicContract {
        declaration_owner: owner.clone(),
        raw_contract: source,
        source_anchor,
        content: Arc::new(EffectivePanicContractContent::new(requirements)),
    });
    for requirement in prepared.content.requirements.iter() {
        if let Some(reference) = requirement.raw_requirement() {
            claimed_requirements.insert(reference.clone());
        }
    }
    raw_by_callable.insert(owner, prepared);
    Ok(())
}

fn prepare_raw_requirements(
    scope: &ArtifactScopeId,
    owner: &ScopedEntityId<CallableEntity>,
    owner_key: &FunctionKey,
    contract: &ScopedRowRef,
    references: &[crate::analysis::facts::encoded::RowRef],
    requirement_rows: &BTreeMap<ScopedRowRef, PreparedPanicRequirementRow>,
) -> Result<Vec<EffectivePanicRequirement>, WorkspaceEffectivePanicContractsError> {
    let mut requirements = Vec::with_capacity(references.len());
    for reference in references {
        let scoped = ScopedRowRef::new(scope.clone(), reference.clone());
        if reference.schema.as_str() != PanicRequirement::ID {
            return Err(
                WorkspaceEffectivePanicContractsError::InvalidRequirementSchema {
                    contract: Box::new(contract.clone()),
                    requirement: Box::new(scoped),
                },
            );
        }
        let row = requirement_rows.get(&scoped).ok_or_else(|| {
            WorkspaceEffectivePanicContractsError::InvalidRequirementReference {
                contract: Box::new(contract.clone()),
                requirement: Box::new(scoped.clone()),
            }
        })?;
        if &row.owner != owner_key {
            return Err(
                WorkspaceEffectivePanicContractsError::RequirementOwnerMismatch {
                    contract: Box::new(contract.clone()),
                    requirement: Box::new(scoped),
                    owner: Box::new(owner.clone()),
                },
            );
        }
        requirements.push((
            row.requirement.ordinal,
            scoped.clone(),
            row.requirement.clone(),
        ));
    }
    requirements.sort_by(|left, right| (left.0, &left.1).cmp(&(right.0, &right.1)));
    for (expected, (ordinal, requirement, _)) in requirements.iter().enumerate() {
        let expected = u32::try_from(expected).map_err(|_| {
            WorkspaceEffectivePanicContractsError::RequirementOrdinalOverflow {
                contract: contract.clone(),
            }
        })?;
        if *ordinal != expected {
            return Err(
                WorkspaceEffectivePanicContractsError::InvalidRequirementOrdinal {
                    contract: Box::new(contract.clone()),
                    requirement: Box::new(requirement.clone()),
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
    BTreeMap<ScopedRowRef, PreparedPanicRequirementRow>,
    WorkspaceEffectivePanicContractsError,
> {
    let rows = view.indexed_rows::<PanicRequirement>().map_err(|source| {
        WorkspaceEffectivePanicContractsError::ReadRequirements {
            scope: scope.clone(),
            source: Box::new(source),
        }
    })?;
    let mut prepared = BTreeMap::new();
    for row in rows {
        let reference = ScopedRowRef::new(scope.clone(), row.reference);
        if program.exact_callable(scope, row.data.owner()).is_none() {
            return Err(
                WorkspaceEffectivePanicContractsError::RequirementOwnerNotIndexed {
                    requirement: reference,
                    owner: *row.data.owner(),
                },
            );
        }
        let normalized_name = row.data.normalized_name();
        if normalized_name.is_empty() {
            return Err(
                WorkspaceEffectivePanicContractsError::EmptyRequirementName {
                    requirement: reference,
                },
            );
        }
        let source_anchor = row
            .data
            .source_anchor()
            .map(|key| {
                let indexed = program.exact_source_anchor(scope, key).ok_or_else(|| {
                    WorkspaceEffectivePanicContractsError::RequirementAnchorNotIndexed {
                        requirement: reference.clone(),
                        key: Box::new(key.clone()),
                    }
                })?;
                Ok(EffectivePanicContractSourceAnchor {
                    id: indexed.id(),
                    reference: indexed.reference().clone(),
                    data: indexed.data().clone(),
                })
            })
            .transpose()?;
        let owner = *row.data.owner();
        let requirement = EffectivePanicRequirement {
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
                PreparedPanicRequirementRow { owner, requirement },
            )
            .is_some()
        {
            return Err(
                WorkspaceEffectivePanicContractsError::DuplicateRequirementRow {
                    requirement: reference,
                },
            );
        }
    }
    Ok(prepared)
}

fn validate_anchor(
    workspace: &WorkspaceFactView<'_>,
    program: &WorkspaceProgramIndex,
    scope: &ArtifactScopeId,
    anchor: Option<&crate::analysis::facts::encoded::EntityRef>,
    contract: &ScopedRowRef,
    _requirement: Option<&ScopedRowRef>,
) -> Result<Option<EffectivePanicContractSourceAnchor>, WorkspaceEffectivePanicContractsError> {
    let Some(anchor) = anchor else {
        return Ok(None);
    };
    let reference = ScopedEntityRef::new(scope.clone(), anchor.clone());
    let data = workspace
        .entity::<SourceAnchorEntity>(&reference)
        .map_err(
            |source| WorkspaceEffectivePanicContractsError::InvalidContractAnchor {
                contract: contract.clone(),
                anchor: Box::new(reference.clone()),
                source: Box::new(source),
            },
        )?;
    let indexed = program
        .exact_source_anchor(scope, data.anchor())
        .filter(|indexed| indexed.reference() == &reference)
        .ok_or_else(
            || WorkspaceEffectivePanicContractsError::ContractAnchorNotIndexed {
                contract: contract.clone(),
                anchor: Box::new(reference),
            },
        )?;
    Ok(Some(EffectivePanicContractSourceAnchor {
        id: indexed.id(),
        reference: indexed.reference().clone(),
        data: indexed.data().clone(),
    }))
}

fn validate_requirement_coverage(
    scope: &ArtifactScopeId,
    all: &BTreeMap<ScopedRowRef, PreparedPanicRequirementRow>,
    referenced: &BTreeSet<ScopedRowRef>,
) -> Result<usize, WorkspaceEffectivePanicContractsError> {
    let mut visits = 0usize;
    for requirement in all.keys() {
        visits = visits.saturating_add(1);
        if !referenced.contains(requirement) {
            return Err(WorkspaceEffectivePanicContractsError::OrphanRequirement {
                scope: scope.clone(),
                requirement: requirement.clone(),
            });
        }
    }
    Ok(visits)
}

fn validate_no_shared_requirement_refs(
    scope: &ArtifactScopeId,
    contracts: &[TypedFact<PanicContractFact>],
) -> Result<(), WorkspaceEffectivePanicContractsError> {
    let mut claims = BTreeSet::new();
    for contract in contracts {
        for reference in &contract.metadata.requirements {
            if reference.schema.as_str() != PanicRequirement::ID {
                continue;
            }
            let requirement = ScopedRowRef::new(scope.clone(), reference.clone());
            if !claims.insert(requirement.clone()) {
                return Err(WorkspaceEffectivePanicContractsError::SharedRequirement {
                    scope: scope.clone(),
                    requirement,
                });
            }
        }
    }
    Ok(())
}

/// Structured failure while preparing or querying effective panic contracts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WorkspaceEffectivePanicContractsError {
    WorkspaceMismatch,
    InvalidBuiltInSchema {
        schema: &'static str,
        reason: String,
    },
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
    ReadRequirements {
        scope: ArtifactScopeId,
        source: Box<ViewError>,
    },
    ReadCallables {
        scope: ArtifactScopeId,
        source: Box<ViewError>,
    },
    CallableNotIndexedAtOpen {
        scope: ArtifactScopeId,
        key: FunctionKey,
    },
    DuplicateCallableAtOpen {
        callable: Box<ScopedEntityId<CallableEntity>>,
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
        first: Box<ScopedRowRef>,
        duplicate: Box<ScopedRowRef>,
    },
    InvalidCallableIdentity {
        callable: Box<ScopedEntityRef>,
    },
    MissingPreparedOverride {
        pattern: String,
    },
    OverrideRequirementOrdinalOverflow {
        pattern: String,
    },
    InvalidRequirementSchema {
        contract: Box<ScopedRowRef>,
        requirement: Box<ScopedRowRef>,
    },
    InvalidRequirementReference {
        contract: Box<ScopedRowRef>,
        requirement: Box<ScopedRowRef>,
    },
    RequirementOwnerNotIndexed {
        requirement: ScopedRowRef,
        owner: FunctionKey,
    },
    DuplicateRequirementRow {
        requirement: ScopedRowRef,
    },
    RequirementOwnerMismatch {
        contract: Box<ScopedRowRef>,
        requirement: Box<ScopedRowRef>,
        owner: Box<ScopedEntityId<CallableEntity>>,
    },
    EmptyRequirementName {
        requirement: ScopedRowRef,
    },
    RequirementAnchorNotIndexed {
        requirement: ScopedRowRef,
        key: Box<crate::analysis::facts::program::SourceAnchorKey>,
    },
    RequirementOrdinalOverflow {
        contract: ScopedRowRef,
    },
    InvalidRequirementOrdinal {
        contract: Box<ScopedRowRef>,
        requirement: Box<ScopedRowRef>,
        expected: u32,
        found: u32,
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
    SharedRequirement {
        scope: ArtifactScopeId,
        requirement: ScopedRowRef,
    },
    OrphanRequirement {
        scope: ArtifactScopeId,
        requirement: ScopedRowRef,
    },
}

impl WorkspaceEffectivePanicContractsError {
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

impl Display for WorkspaceEffectivePanicContractsError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkspaceMismatch => formatter.write_str(
                "effective panic contract index belongs to a replacement workspace view",
            ),
            Self::InvalidBuiltInSchema { schema, reason } => {
                fmt_invalid_built_in_schema(formatter, schema, reason)
            }
            Self::SchemaUnavailable { scope, schema } => {
                fmt_schema_unavailable(formatter, scope, schema)
            }
            Self::InvalidTableKind {
                scope,
                schema,
                found,
            } => fmt_invalid_table_kind(formatter, scope, schema, *found),
            Self::MissingTable { scope, schema } => fmt_missing_table(formatter, scope, schema),
            Self::Program { .. } => formatter.write_str("permanent program index is invalid"),
            Self::Workspace { .. } => formatter.write_str("workspace artifact lookup failed"),
            Self::ReadContracts { scope, .. } => fmt_read_contracts(formatter, scope),
            Self::ReadRequirements { scope, .. } => fmt_read_requirements(formatter, scope),
            Self::ReadCallables { scope, .. } => fmt_read_callables(formatter, scope),
            Self::CallableNotIndexedAtOpen { scope, key } => {
                fmt_callable_not_indexed(formatter, scope, key)
            }
            Self::DuplicateCallableAtOpen { callable } => {
                fmt_duplicate_callable(formatter, callable)
            }
            Self::MissingOwner { contract } => fmt_missing_owner(formatter, contract),
            Self::InvalidOwner {
                contract, owner, ..
            } => fmt_invalid_owner(formatter, contract, owner),
            Self::OwnerNotIndexed { contract, owner } => {
                fmt_owner_not_indexed(formatter, contract, owner)
            }
            Self::DuplicateOwner {
                owner,
                first,
                duplicate,
            } => fmt_duplicate_owner(formatter, owner, first, duplicate),
            Self::InvalidCallableIdentity { callable } => {
                fmt_invalid_callable_identity(formatter, callable)
            }
            Self::MissingPreparedOverride { pattern } => {
                fmt_missing_prepared_override(formatter, pattern)
            }
            Self::OverrideRequirementOrdinalOverflow { pattern } => {
                fmt_override_ordinal_overflow(formatter, pattern)
            }
            Self::InvalidRequirementSchema {
                contract,
                requirement,
            } => fmt_invalid_requirement_schema(formatter, contract, requirement),
            Self::InvalidRequirementReference {
                contract,
                requirement,
            } => fmt_invalid_requirement_reference(formatter, contract, requirement),
            Self::RequirementOwnerNotIndexed { requirement, owner } => {
                fmt_requirement_owner_not_indexed(formatter, requirement, owner)
            }
            Self::DuplicateRequirementRow { requirement } => {
                fmt_duplicate_requirement(formatter, requirement)
            }
            Self::RequirementOwnerMismatch {
                contract,
                requirement,
                owner,
            } => fmt_requirement_owner_mismatch(formatter, contract, requirement, owner),
            Self::EmptyRequirementName { requirement } => {
                fmt_empty_requirement_name(formatter, requirement)
            }
            Self::RequirementAnchorNotIndexed { requirement, key } => {
                fmt_requirement_anchor_not_indexed(formatter, requirement, key)
            }
            Self::RequirementOrdinalOverflow { contract } => {
                fmt_requirement_ordinal_overflow(formatter, contract)
            }
            Self::InvalidRequirementOrdinal {
                contract,
                requirement,
                expected,
                found,
            } => {
                fmt_invalid_requirement_ordinal(formatter, contract, requirement, *expected, *found)
            }
            Self::InvalidContractAnchor {
                contract, anchor, ..
            } => fmt_invalid_contract_anchor(formatter, contract, anchor),
            Self::ContractAnchorNotIndexed { contract, anchor } => {
                fmt_contract_anchor_not_indexed(formatter, contract, anchor)
            }
            Self::SharedRequirement { scope, requirement } => {
                fmt_shared_requirement(formatter, scope, requirement)
            }
            Self::OrphanRequirement { scope, requirement } => {
                fmt_orphan_requirement(formatter, scope, requirement)
            }
        }
    }
}

fn fmt_invalid_built_in_schema(
    formatter: &mut Formatter<'_>,
    schema: &str,
    reason: &str,
) -> fmt::Result {
    write!(
        formatter,
        "built-in panic schema `{schema}` is invalid: {reason}"
    )
}

fn fmt_schema_unavailable(
    formatter: &mut Formatter<'_>,
    scope: &ArtifactScopeId,
    schema: &SchemaId,
) -> fmt::Result {
    write!(
        formatter,
        "artifact scope `{scope}` has no registered panic schema `{schema}`"
    )
}

fn fmt_invalid_table_kind(
    formatter: &mut Formatter<'_>,
    scope: &ArtifactScopeId,
    schema: &SchemaId,
    found: TableKind,
) -> fmt::Result {
    write!(
        formatter,
        "artifact scope `{scope}` registers panic schema `{schema}` as {found:?}"
    )
}

fn fmt_missing_table(
    formatter: &mut Formatter<'_>,
    scope: &ArtifactScopeId,
    schema: &SchemaId,
) -> fmt::Result {
    write!(
        formatter,
        "artifact scope `{scope}` is missing required panic table `{schema}`"
    )
}

fn fmt_read_contracts(formatter: &mut Formatter<'_>, scope: &ArtifactScopeId) -> fmt::Result {
    write!(
        formatter,
        "cannot read panic contracts in artifact scope `{scope}`"
    )
}

fn fmt_read_requirements(formatter: &mut Formatter<'_>, scope: &ArtifactScopeId) -> fmt::Result {
    write!(
        formatter,
        "cannot read panic requirements in artifact scope `{scope}`"
    )
}

fn fmt_read_callables(formatter: &mut Formatter<'_>, scope: &ArtifactScopeId) -> fmt::Result {
    write!(
        formatter,
        "cannot read callable rows in artifact scope `{scope}`"
    )
}

fn fmt_callable_not_indexed(
    formatter: &mut Formatter<'_>,
    scope: &ArtifactScopeId,
    key: &FunctionKey,
) -> fmt::Result {
    write!(
        formatter,
        "callable {key:?} in artifact scope `{scope}` is absent from the permanent program index"
    )
}

fn fmt_duplicate_callable(
    formatter: &mut Formatter<'_>,
    callable: &ScopedEntityId<CallableEntity>,
) -> fmt::Result {
    write!(
        formatter,
        "callable {callable:?} appears more than once while preparing panic contracts"
    )
}

fn fmt_missing_owner(formatter: &mut Formatter<'_>, contract: &ScopedRowRef) -> fmt::Result {
    write!(
        formatter,
        "panic contract {contract:?} has no callable owner"
    )
}

fn fmt_invalid_owner(
    formatter: &mut Formatter<'_>,
    contract: &ScopedRowRef,
    owner: &ScopedEntityRef,
) -> fmt::Result {
    write!(
        formatter,
        "panic contract {contract:?} has invalid callable owner {owner:?}"
    )
}

fn fmt_owner_not_indexed(
    formatter: &mut Formatter<'_>,
    contract: &ScopedRowRef,
    owner: &ScopedEntityRef,
) -> fmt::Result {
    write!(
        formatter,
        "panic contract {contract:?} owner {owner:?} is absent from the permanent program index"
    )
}

fn fmt_duplicate_owner(
    formatter: &mut Formatter<'_>,
    owner: &ScopedEntityId<CallableEntity>,
    first: &ScopedRowRef,
    duplicate: &ScopedRowRef,
) -> fmt::Result {
    write!(
        formatter,
        "callable {owner:?} owns panic contracts {first:?} and {duplicate:?}"
    )
}

fn fmt_invalid_callable_identity(
    formatter: &mut Formatter<'_>,
    callable: &ScopedEntityRef,
) -> fmt::Result {
    write!(
        formatter,
        "callable query {callable:?} is not an exact identity prepared by this index"
    )
}

fn fmt_missing_prepared_override(formatter: &mut Formatter<'_>, pattern: &str) -> fmt::Result {
    write!(
        formatter,
        "panic contract override pattern {pattern:?} has no prepared value"
    )
}

fn fmt_override_ordinal_overflow(formatter: &mut Formatter<'_>, pattern: &str) -> fmt::Result {
    write!(
        formatter,
        "panic contract override pattern {pattern:?} declares too many requirements"
    )
}

fn fmt_invalid_requirement_schema(
    formatter: &mut Formatter<'_>,
    contract: &ScopedRowRef,
    requirement: &ScopedRowRef,
) -> fmt::Result {
    write!(
        formatter,
        "panic contract {contract:?} references non-panic requirement {requirement:?}"
    )
}

fn fmt_invalid_requirement_reference(
    formatter: &mut Formatter<'_>,
    contract: &ScopedRowRef,
    requirement: &ScopedRowRef,
) -> fmt::Result {
    write!(
        formatter,
        "panic contract {contract:?} references unavailable requirement {requirement:?}"
    )
}

fn fmt_requirement_owner_not_indexed(
    formatter: &mut Formatter<'_>,
    requirement: &ScopedRowRef,
    owner: &FunctionKey,
) -> fmt::Result {
    write!(
        formatter,
        "panic requirement {requirement:?} owner {owner:?} is absent from the permanent program index"
    )
}

fn fmt_duplicate_requirement(
    formatter: &mut Formatter<'_>,
    requirement: &ScopedRowRef,
) -> fmt::Result {
    write!(
        formatter,
        "panic requirement {requirement:?} appears more than once while preparing contracts"
    )
}

fn fmt_requirement_owner_mismatch(
    formatter: &mut Formatter<'_>,
    contract: &ScopedRowRef,
    requirement: &ScopedRowRef,
    owner: &ScopedEntityId<CallableEntity>,
) -> fmt::Result {
    write!(
        formatter,
        "panic contract {contract:?} requirement {requirement:?} does not belong to callable {owner:?}"
    )
}

fn fmt_empty_requirement_name(
    formatter: &mut Formatter<'_>,
    requirement: &ScopedRowRef,
) -> fmt::Result {
    write!(
        formatter,
        "panic requirement {requirement:?} has an empty normalized name"
    )
}

fn fmt_requirement_anchor_not_indexed(
    formatter: &mut Formatter<'_>,
    requirement: &ScopedRowRef,
    key: &crate::analysis::facts::program::SourceAnchorKey,
) -> fmt::Result {
    write!(
        formatter,
        "panic requirement {requirement:?} names unindexed source anchor {key:?}"
    )
}

fn fmt_requirement_ordinal_overflow(
    formatter: &mut Formatter<'_>,
    contract: &ScopedRowRef,
) -> fmt::Result {
    write!(
        formatter,
        "panic contract {contract:?} declares too many requirements"
    )
}

fn fmt_invalid_requirement_ordinal(
    formatter: &mut Formatter<'_>,
    contract: &ScopedRowRef,
    requirement: &ScopedRowRef,
    expected: u32,
    found: u32,
) -> fmt::Result {
    write!(
        formatter,
        "panic contract {contract:?} requirement {requirement:?} has ordinal {found}, expected {expected}"
    )
}

fn fmt_invalid_contract_anchor(
    formatter: &mut Formatter<'_>,
    contract: &ScopedRowRef,
    anchor: &ScopedEntityRef,
) -> fmt::Result {
    write!(
        formatter,
        "panic contract {contract:?} has invalid source anchor {anchor:?}"
    )
}

fn fmt_contract_anchor_not_indexed(
    formatter: &mut Formatter<'_>,
    contract: &ScopedRowRef,
    anchor: &ScopedEntityRef,
) -> fmt::Result {
    write!(
        formatter,
        "panic contract {contract:?} source anchor {anchor:?} is absent from the permanent program index"
    )
}

fn fmt_shared_requirement(
    formatter: &mut Formatter<'_>,
    scope: &ArtifactScopeId,
    requirement: &ScopedRowRef,
) -> fmt::Result {
    write!(
        formatter,
        "panic requirement {requirement:?} in artifact scope `{scope}` is referenced by multiple contracts"
    )
}

fn fmt_orphan_requirement(
    formatter: &mut Formatter<'_>,
    scope: &ArtifactScopeId,
    requirement: &ScopedRowRef,
) -> fmt::Result {
    write!(
        formatter,
        "panic requirement {requirement:?} in artifact scope `{scope}` is not referenced by a contract"
    )
}

impl Error for WorkspaceEffectivePanicContractsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Program { source } => Some(source.as_ref()),
            Self::Workspace { source }
            | Self::InvalidOwner { source, .. }
            | Self::InvalidContractAnchor { source, .. } => Some(source.as_ref()),
            Self::ReadContracts { source, .. }
            | Self::ReadRequirements { source, .. }
            | Self::ReadCallables { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::super::contracts::{PanicContractFact, PanicRequirement};
    use super::{
        EffectivePanicContractOrigin, WorkspaceEffectivePanicContracts,
        WorkspaceEffectivePanicContractsError, index_contract,
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
    use crate::contracts::{
        ContractDocOverrides, panic_markdown_parse_count, reset_panic_markdown_parse_count,
    };
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
            let metadata = FactMeta::new(PassId::new("test.panic.contract-index").unwrap())
                .with_owner(handles.get(owner).unwrap())
                .unwrap();
            builder
                .insert_fact(&PanicContractFact::new(), metadata)
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

    fn artifact_with_requirements(
        registry: &AnalysisRegistry<()>,
        owner: FunctionKey,
        requirements: &[PanicRequirement],
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
        let mut metadata = FactMeta::new(PassId::new("test.panic.contract-index").unwrap())
            .with_owner(&callable)
            .unwrap();
        for requirement in requirements {
            let handle = builder.insert_requirement(requirement).unwrap();
            metadata = metadata.with_requirement(&handle).unwrap();
        }
        builder
            .insert_fact(&PanicContractFact::new(), metadata)
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
            .insert_entity(&SourceAnchorEntity::new(contract_key))
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
            .insert_requirement(&PanicRequirement::new(
                owner,
                0,
                "ready",
                "ready condition",
                Some(requirement_key),
            ))
            .unwrap();
        let metadata = FactMeta::new(PassId::new("test.panic.contract-index").unwrap())
            .with_owner(&callable)
            .unwrap()
            .with_anchor(&contract_anchor)
            .unwrap()
            .with_requirement(&requirement)
            .unwrap();
        builder
            .insert_fact(&PanicContractFact::new(), metadata)
            .unwrap();
        builder.finalize(registry.schemas()).unwrap()
    }

    fn artifact_with_unclaimed_anchor(
        registry: &AnalysisRegistry<()>,
        owner: FunctionKey,
        anchor: SourceAnchorKey,
    ) -> ArtifactFactIr {
        let mut builder = ArtifactDbBuilder::new();
        for descriptor in registry.schemas().descriptors() {
            builder.declare_table(descriptor).unwrap();
        }
        builder
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
                anchor.file(),
                anchor.file(),
                "verified",
                100,
            ))
            .unwrap();
        let anchor = builder
            .insert_entity(&SourceAnchorEntity::new(anchor))
            .unwrap();
        builder
            .relate(&anchor, &file, &SourceAnchorInFile::new())
            .unwrap();
        builder.finalize(registry.schemas()).unwrap()
    }

    fn contract_metadata_mut(
        artifact: &mut ArtifactFactIr,
    ) -> &mut crate::analysis::facts::encoded::FactIndexRow {
        artifact
            .fact_index
            .iter_mut()
            .find(|metadata| metadata.fact.schema.as_str() == PanicContractFact::ID)
            .expect("fixture contains one panic contract")
    }

    fn panic_requirement_table_mut(
        artifact: &mut ArtifactFactIr,
    ) -> &mut crate::analysis::facts::encoded::EncodedTable {
        artifact
            .tables
            .iter_mut()
            .find(|table| table.schema.as_str() == PanicRequirement::ID)
            .expect("fixture contains panic requirement table")
    }

    #[test]
    fn full_raw_contract_preserves_provenance_order_lookup_and_duplicate_groups() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let owner = callable_key(13, 1, None);
        let artifact = artifact_with_requirements(
            &registry,
            owner,
            &[
                PanicRequirement::new(owner, 0, "Index_In-Bounds", "first", None),
                PanicRequirement::new(owner, 1, "ready", "second", None),
                PanicRequirement::new(owner, 2, "index in bounds", "third", None),
            ],
        );
        let (scope, workspace, program) = workspace_and_program(&artifact, &registry, 13);
        let contracts = WorkspaceEffectivePanicContracts::open(
            &workspace,
            &program,
            &ContractDocOverrides::default(),
        )
        .unwrap();
        let queried = program.exact_callable(&scope, &owner).unwrap().id();

        let contract = contracts
            .effective_panic_contract(&workspace, &queried)
            .unwrap()
            .unwrap();

        assert_eq!(contract.queried_callable(), &queried);
        assert_eq!(contract.declaration_owner(), &queried);
        assert_eq!(contract.origin(), EffectivePanicContractOrigin::RawExact);
        assert!(contract.raw_contract().is_some());
        assert!(contract.source_anchor().is_none());
        assert_eq!(
            contract
                .requirements()
                .iter()
                .map(|requirement| (
                    requirement.ordinal(),
                    requirement.name(),
                    requirement.normalized_name(),
                    requirement.condition(),
                    requirement.raw_requirement().is_some(),
                ))
                .collect::<Vec<_>>(),
            vec![
                (0, "Index_In-Bounds", "index in bounds", "first", true),
                (1, "ready", "ready", "second", true),
                (2, "index in bounds", "index in bounds", "third", true),
            ]
        );
        assert_eq!(
            contract
                .requirements_by_normalized_name("index in bounds")
                .iter()
                .map(super::EffectivePanicRequirement::ordinal)
                .collect::<Vec<_>>(),
            vec![0, 2]
        );
        assert_eq!(contract.duplicate_requirement_groups().len(), 1);
        assert_eq!(
            contract.duplicate_requirement_groups()[0].normalized_name(),
            "index in bounds"
        );
        assert_eq!(
            contract.duplicate_requirement_groups()[0]
                .requirements()
                .iter()
                .map(super::EffectivePanicRequirement::ordinal)
                .collect::<Vec<_>>(),
            vec![0, 2]
        );
    }

    #[test]
    fn raw_requirement_order_uses_ordinals_not_canonical_reference_order() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let owner = callable_key(39, 1, None);
        let artifact = artifact_with_requirements(
            &registry,
            owner,
            &[
                PanicRequirement::new(owner, 0, "zero", "z condition", None),
                PanicRequirement::new(owner, 1, "one", "a condition", None),
            ],
        );
        let (scope, workspace, program) = workspace_and_program(&artifact, &registry, 39);
        let raw = workspace
            .artifact(&scope)
            .unwrap()
            .facts::<PanicContractFact>()
            .unwrap()
            .pop()
            .unwrap();
        let references = raw
            .metadata
            .requirements
            .into_iter()
            .map(|reference| {
                crate::analysis::facts::workspace::ScopedRowRef::new(scope.clone(), reference)
            })
            .collect::<Vec<_>>();
        let stored_ordinals = references
            .iter()
            .map(|reference| {
                workspace
                    .row::<PanicRequirement>(reference)
                    .unwrap()
                    .data
                    .ordinal()
            })
            .collect::<Vec<_>>();
        assert_eq!(stored_ordinals, vec![1, 0]);
        let expected_by_ordinal = stored_ordinals
            .iter()
            .copied()
            .zip(references.iter())
            .collect::<BTreeMap<_, _>>();
        let contracts = WorkspaceEffectivePanicContracts::open(
            &workspace,
            &program,
            &ContractDocOverrides::default(),
        )
        .unwrap();
        let owner = program.exact_callable(&scope, &owner).unwrap().id();

        let contract = contracts
            .effective_panic_contract(&workspace, &owner)
            .unwrap()
            .unwrap();

        assert_eq!(
            contract
                .requirements()
                .iter()
                .map(|requirement| (requirement.ordinal(), requirement.name()))
                .collect::<Vec<_>>(),
            vec![(0, "zero"), (1, "one")]
        );
        for requirement in contract.requirements() {
            assert_eq!(
                requirement.raw_requirement(),
                Some(*expected_by_ordinal.get(&requirement.ordinal()).unwrap())
            );
        }
    }

    #[test]
    fn full_raw_contract_retains_verified_contract_and_requirement_anchors() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let owner = callable_key(17, 1, None);
        let artifact = artifact_with_anchored_contract_and_requirement(&registry, owner);
        let (scope, workspace, program) = workspace_and_program(&artifact, &registry, 17);
        let contracts = WorkspaceEffectivePanicContracts::open(
            &workspace,
            &program,
            &ContractDocOverrides::default(),
        )
        .unwrap();
        let owner = program.exact_callable(&scope, &owner).unwrap().id();

        let contract = contracts
            .effective_panic_contract(&workspace, &owner)
            .unwrap()
            .unwrap();
        let contract_anchor = contract.source_anchor().unwrap();
        assert_eq!(contract_anchor.id().scope(), &scope);
        assert_eq!(contract_anchor.reference().scope(), &scope);
        assert_eq!(contract_anchor.data().anchor().byte_start(), 10);
        let requirement_anchor = contract.requirements()[0].source_anchor().unwrap();
        assert_eq!(requirement_anchor.id().scope(), &scope);
        assert_eq!(requirement_anchor.reference().scope(), &scope);
        assert_eq!(requirement_anchor.data().anchor().byte_start(), 30);
    }

    #[test]
    fn wrong_schema_and_dangling_contract_anchors_are_rejected() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let owner = callable_key(40, 1, None);
        let artifact = artifact_with_anchored_contract_and_requirement(&registry, owner);
        let (scope, workspace, program) = workspace_and_program(&artifact, &registry, 40);
        let requirements =
            super::prepare_requirement_table(&program, &scope, workspace.artifact(&scope).unwrap())
                .unwrap();

        let mut wrong_schema = workspace
            .artifact(&scope)
            .unwrap()
            .facts::<PanicContractFact>()
            .unwrap()
            .pop()
            .unwrap();
        wrong_schema.metadata.anchor.as_mut().unwrap().schema =
            crate::analysis::facts::schema::SchemaId::new(SourceFileEntity::ID).unwrap();
        assert!(matches!(
            index_contract(
                &workspace,
                &program,
                &scope,
                wrong_schema,
                &requirements,
                &mut BTreeMap::new(),
                &mut BTreeSet::new(),
            ),
            Err(WorkspaceEffectivePanicContractsError::InvalidContractAnchor { .. })
        ));

        let mut dangling = workspace
            .artifact(&scope)
            .unwrap()
            .facts::<PanicContractFact>()
            .unwrap()
            .pop()
            .unwrap();
        dangling.metadata.anchor.as_mut().unwrap().row = u32::MAX;
        assert!(matches!(
            index_contract(
                &workspace,
                &program,
                &scope,
                dangling,
                &requirements,
                &mut BTreeMap::new(),
                &mut BTreeSet::new(),
            ),
            Err(WorkspaceEffectivePanicContractsError::InvalidContractAnchor { .. })
        ));
    }

    #[test]
    fn full_raw_generic_contract_keeps_queried_and_declaring_callables_distinct() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let generic = callable_key(14, 1, None);
        let exact = callable_key(14, 1, Some(141));
        let mut builder = ArtifactDbBuilder::new();
        for descriptor in registry.schemas().descriptors() {
            builder.declare_table(descriptor).unwrap();
        }
        let generic_handle = builder
            .insert_entity(&CallableEntity::new(
                generic,
                "crate::generic",
                false,
                false,
                false,
                false,
                vec![String::from("crate::generic")],
            ))
            .unwrap();
        builder
            .insert_entity(&CallableEntity::new(
                exact,
                "crate::generic::<u8>",
                false,
                false,
                false,
                false,
                vec![String::from("crate::generic")],
            ))
            .unwrap();
        let requirement = builder
            .insert_requirement(&PanicRequirement::new(
                generic,
                0,
                "ready",
                "the value is ready",
                None,
            ))
            .unwrap();
        let metadata = FactMeta::new(PassId::new("test.panic.contract-index").unwrap())
            .with_owner(&generic_handle)
            .unwrap()
            .with_requirement(&requirement)
            .unwrap();
        builder
            .insert_fact(&PanicContractFact::new(), metadata)
            .unwrap();
        let artifact = builder.finalize(registry.schemas()).unwrap();
        let (scope, workspace, program) = workspace_and_program(&artifact, &registry, 14);
        let contracts = WorkspaceEffectivePanicContracts::open(
            &workspace,
            &program,
            &ContractDocOverrides::default(),
        )
        .unwrap();
        let generic = program.exact_callable(&scope, &generic).unwrap().id();
        let exact = program.exact_callable(&scope, &exact).unwrap().id();

        let contract = contracts
            .effective_panic_contract(&workspace, &exact)
            .unwrap()
            .unwrap();

        assert_eq!(contract.queried_callable(), &exact);
        assert_eq!(contract.declaration_owner(), &generic);
        assert_eq!(contract.origin(), EffectivePanicContractOrigin::RawGeneric);
        assert!(contract.raw_contract().is_some());
        assert_eq!(contract.requirements()[0].name(), "ready");
    }

    #[test]
    fn full_override_is_value_only_total_and_preserves_first_duplicate_pattern() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let callable = callable_key(15, 1, None);
        let artifact = artifact(
            &registry,
            &[(
                callable,
                "dependency::Widget::run",
                &["dependency::Widget::run"],
            )],
            &[callable],
        );
        let (scope, workspace, program) = workspace_and_program(&artifact, &registry, 15);
        let overrides = ContractDocOverrides::new(vec![
            (
                String::from("dependency::Widget::run"),
                String::from(
                    "# Panics\n- zeta: first\n- alpha: second\n- zeta: third\n- alpha: fourth",
                ),
            ),
            (
                String::from("dependency::Widget::run"),
                String::from("# Notes\nThis duplicate must not replace the first."),
            ),
        ])
        .unwrap();
        reset_panic_markdown_parse_count();
        let contracts =
            WorkspaceEffectivePanicContracts::open(&workspace, &program, &overrides).unwrap();
        assert_eq!(panic_markdown_parse_count(), 2);
        drop(overrides);
        let callable = program.exact_callable(&scope, &callable).unwrap().id();

        let contract = contracts
            .effective_panic_contract(&workspace, &callable)
            .unwrap()
            .unwrap();

        assert_eq!(contract.queried_callable(), &callable);
        assert_eq!(contract.declaration_owner(), &callable);
        assert_eq!(contract.origin(), EffectivePanicContractOrigin::Override);
        assert!(contract.raw_contract().is_none());
        assert!(contract.source_anchor().is_none());
        assert!(
            contract
                .requirements()
                .iter()
                .all(|requirement| requirement.raw_requirement().is_none()
                    && requirement.source_anchor().is_none())
        );
        assert_eq!(
            contract
                .requirements()
                .iter()
                .map(super::EffectivePanicRequirement::name)
                .collect::<Vec<_>>(),
            vec!["zeta", "alpha", "zeta", "alpha"]
        );
        assert_eq!(
            contract
                .duplicate_requirement_groups()
                .iter()
                .map(super::EffectivePanicRequirementGroup::normalized_name)
                .collect::<Vec<_>>(),
            vec!["alpha", "zeta"]
        );
        for _ in 0..3 {
            assert!(
                contracts
                    .effective_panic_contract(&workspace, &callable)
                    .unwrap()
                    .is_some()
            );
        }
        assert_eq!(panic_markdown_parse_count(), 2);
    }

    #[test]
    fn override_without_panics_totally_removes_full_raw_contract() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let callable = callable_key(16, 1, None);
        let artifact = artifact(
            &registry,
            &[(callable, "dependency::run", &["dependency::run"])],
            &[callable],
        );
        let (scope, workspace, program) = workspace_and_program(&artifact, &registry, 16);
        let overrides = ContractDocOverrides::new(vec![(
            String::from("dependency::run"),
            String::from("# Notes\nNo panic contract."),
        )])
        .unwrap();
        let contracts =
            WorkspaceEffectivePanicContracts::open(&workspace, &program, &overrides).unwrap();
        let callable = program.exact_callable(&scope, &callable).unwrap().id();

        assert!(
            contracts
                .effective_panic_contract(&workspace, &callable)
                .unwrap()
                .is_none()
        );
        assert!(
            !contracts
                .has_effective_panic_contract(&workspace, &callable)
                .unwrap()
        );
    }

    #[test]
    fn requirement_owner_mismatch_is_rejected() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let owner = callable_key(18, 1, None);
        let other = callable_key(18, 2, None);
        let mut builder = ArtifactDbBuilder::new();
        for descriptor in registry.schemas().descriptors() {
            builder.declare_table(descriptor).unwrap();
        }
        let first = builder
            .insert_entity(&CallableEntity::new(
                owner,
                "crate::owner",
                false,
                false,
                false,
                false,
                vec![String::from("crate::owner")],
            ))
            .unwrap();
        builder
            .insert_entity(&CallableEntity::new(
                other,
                "crate::other",
                false,
                false,
                false,
                false,
                vec![String::from("crate::other")],
            ))
            .unwrap();
        let requirement = builder
            .insert_requirement(&PanicRequirement::new(other, 0, "ready", "condition", None))
            .unwrap();
        let metadata = FactMeta::new(PassId::new("test.panic.contract-index").unwrap())
            .with_owner(&first)
            .unwrap()
            .with_requirement(&requirement)
            .unwrap();
        builder
            .insert_fact(&PanicContractFact::new(), metadata)
            .unwrap();
        let artifact = builder.finalize(registry.schemas()).unwrap();
        let (_, workspace, program) = workspace_and_program(&artifact, &registry, 18);

        assert!(matches!(
            WorkspaceEffectivePanicContracts::open(
                &workspace,
                &program,
                &ContractDocOverrides::default(),
            ),
            Err(WorkspaceEffectivePanicContractsError::RequirementOwnerMismatch { .. })
        ));
    }

    #[test]
    fn invalid_requirement_ordinals_and_normalized_empty_names_are_rejected() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let owner = callable_key(19, 1, None);
        for requirements in [
            vec![PanicRequirement::new(owner, 1, "ready", "condition", None)],
            vec![
                PanicRequirement::new(owner, 0, "first", "condition", None),
                PanicRequirement::new(owner, 2, "third", "condition", None),
            ],
            vec![
                PanicRequirement::new(owner, 0, "first", "condition", None),
                PanicRequirement::new(owner, 0, "again", "condition", None),
            ],
        ] {
            let artifact = artifact_with_requirements(&registry, owner, &requirements);
            let (_, workspace, program) = workspace_and_program(&artifact, &registry, 19);
            assert!(matches!(
                WorkspaceEffectivePanicContracts::open(
                    &workspace,
                    &program,
                    &ContractDocOverrides::default(),
                ),
                Err(WorkspaceEffectivePanicContractsError::InvalidRequirementOrdinal { .. })
            ));
        }

        let artifact = artifact_with_requirements(
            &registry,
            owner,
            &[PanicRequirement::new(owner, 0, "---", "condition", None)],
        );
        let (_, workspace, program) = workspace_and_program(&artifact, &registry, 19);
        assert!(matches!(
            WorkspaceEffectivePanicContracts::open(
                &workspace,
                &program,
                &ContractDocOverrides::default(),
            ),
            Err(WorkspaceEffectivePanicContractsError::EmptyRequirementName { .. })
        ));
    }

    #[test]
    fn orphan_and_malformed_orphan_requirements_are_rejected() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let owner = callable_key(20, 1, None);
        let mut orphan = artifact_with_requirements(
            &registry,
            owner,
            &[PanicRequirement::new(owner, 0, "ready", "condition", None)],
        );
        contract_metadata_mut(&mut orphan).requirements.clear();
        let (_, workspace, program) = workspace_and_program(&orphan, &registry, 20);
        assert!(matches!(
            WorkspaceEffectivePanicContracts::open(
                &workspace,
                &program,
                &ContractDocOverrides::default(),
            ),
            Err(WorkspaceEffectivePanicContractsError::OrphanRequirement { .. })
        ));

        let mut malformed = orphan;
        panic_requirement_table_mut(&mut malformed).rows[0].data["name"] = serde_json::json!("---");
        let (_, workspace, program) = workspace_and_program(&malformed, &registry, 20);
        assert!(matches!(
            WorkspaceEffectivePanicContracts::open(
                &workspace,
                &program,
                &ContractDocOverrides::default(),
            ),
            Err(WorkspaceEffectivePanicContractsError::EmptyRequirementName { .. })
        ));
    }

    #[test]
    fn wrong_schema_and_dangling_requirement_references_are_rejected() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let owner = callable_key(21, 1, None);
        let valid = artifact_with_requirements(
            &registry,
            owner,
            &[PanicRequirement::new(owner, 0, "ready", "condition", None)],
        );
        let (scope, workspace, program) = workspace_and_program(&valid, &registry, 21);
        let requirements =
            super::prepare_requirement_table(&program, &scope, workspace.artifact(&scope).unwrap())
                .unwrap();
        let mut wrong_schema = workspace
            .artifact(&scope)
            .unwrap()
            .facts::<PanicContractFact>()
            .unwrap()
            .pop()
            .unwrap();
        wrong_schema.metadata.requirements[0].schema =
            crate::analysis::facts::schema::SchemaId::new(
                crate::analysis::facts::safety::SafetyRequirement::ID,
            )
            .unwrap();
        assert!(matches!(
            index_contract(
                &workspace,
                &program,
                &scope,
                wrong_schema,
                &requirements,
                &mut BTreeMap::new(),
                &mut BTreeSet::new(),
            ),
            Err(WorkspaceEffectivePanicContractsError::InvalidRequirementSchema { .. })
        ));

        let mut dangling = workspace
            .artifact(&scope)
            .unwrap()
            .facts::<PanicContractFact>()
            .unwrap()
            .pop()
            .unwrap();
        dangling.metadata.requirements[0].row = u32::MAX;
        assert!(matches!(
            index_contract(
                &workspace,
                &program,
                &scope,
                dangling,
                &requirements,
                &mut BTreeMap::new(),
                &mut BTreeSet::new(),
            ),
            Err(WorkspaceEffectivePanicContractsError::InvalidRequirementReference { .. })
        ));
    }

    #[test]
    fn one_requirement_shared_by_two_contracts_is_rejected() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let first = callable_key(22, 1, None);
        let second = callable_key(22, 2, None);
        let mut builder = ArtifactDbBuilder::new();
        for descriptor in registry.schemas().descriptors() {
            builder.declare_table(descriptor).unwrap();
        }
        let first_owner = builder
            .insert_entity(&CallableEntity::new(
                first,
                "crate::first",
                false,
                false,
                false,
                false,
                vec![String::from("crate::first")],
            ))
            .unwrap();
        let second_owner = builder
            .insert_entity(&CallableEntity::new(
                second,
                "crate::second",
                false,
                false,
                false,
                false,
                vec![String::from("crate::second")],
            ))
            .unwrap();
        let requirement = builder
            .insert_requirement(&PanicRequirement::new(first, 0, "ready", "condition", None))
            .unwrap();
        for owner in [&first_owner, &second_owner] {
            let metadata = FactMeta::new(PassId::new("test.panic.contract-index").unwrap())
                .with_owner(owner)
                .unwrap()
                .with_requirement(&requirement)
                .unwrap();
            builder
                .insert_fact(&PanicContractFact::new(), metadata)
                .unwrap();
        }
        let artifact = builder.finalize(registry.schemas()).unwrap();
        let (_, workspace, program) = workspace_and_program(&artifact, &registry, 22);

        assert!(matches!(
            WorkspaceEffectivePanicContracts::open(
                &workspace,
                &program,
                &ContractDocOverrides::default(),
            ),
            Err(WorkspaceEffectivePanicContractsError::SharedRequirement { .. })
        ));
    }

    #[test]
    fn unindexed_requirement_owner_and_anchor_are_rejected_before_orphan_coverage() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let owner = callable_key(23, 1, None);
        let missing = callable_key(23, 2, None);
        let mut unindexed_owner = artifact_with_requirements(
            &registry,
            owner,
            &[PanicRequirement::new(
                missing,
                0,
                "ready",
                "condition",
                None,
            )],
        );
        contract_metadata_mut(&mut unindexed_owner)
            .requirements
            .clear();
        let (_, workspace, program) = workspace_and_program(&unindexed_owner, &registry, 23);
        assert!(matches!(
            WorkspaceEffectivePanicContracts::open(
                &workspace,
                &program,
                &ContractDocOverrides::default(),
            ),
            Err(WorkspaceEffectivePanicContractsError::RequirementOwnerNotIndexed { .. })
        ));

        let missing_anchor = SourceAnchorKey::new("missing.rs", 1, 2);
        let mut unindexed_anchor = artifact_with_requirements(
            &registry,
            owner,
            &[PanicRequirement::new(
                owner,
                0,
                "ready",
                "condition",
                Some(missing_anchor),
            )],
        );
        contract_metadata_mut(&mut unindexed_anchor)
            .requirements
            .clear();
        let (_, workspace, program) = workspace_and_program(&unindexed_anchor, &registry, 23);
        assert!(matches!(
            WorkspaceEffectivePanicContracts::open(
                &workspace,
                &program,
                &ContractDocOverrides::default(),
            ),
            Err(WorkspaceEffectivePanicContractsError::RequirementAnchorNotIndexed { .. })
        ));
    }

    #[test]
    fn requirement_anchor_in_only_another_scope_is_rejected() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let first_owner = callable_key(27, 1, None);
        let second_owner = callable_key(28, 1, None);
        let shared_anchor = SourceAnchorKey::new("shared.rs", 10, 20);
        let first = artifact_with_requirements(
            &registry,
            first_owner,
            &[PanicRequirement::new(
                first_owner,
                0,
                "ready",
                "condition",
                Some(shared_anchor.clone()),
            )],
        );
        let second = artifact_with_unclaimed_anchor(&registry, second_owner, shared_anchor);
        let first_scope = ArtifactScopeId::for_in_memory(27, 0);
        let second_scope = ArtifactScopeId::for_in_memory(28, 0);
        let workspace = WorkspaceFactView::compose([
            (
                first_scope.clone(),
                ArtifactDbView::open(&first, registry.schemas()).unwrap(),
            ),
            (
                second_scope.clone(),
                ArtifactDbView::open(&second, registry.schemas()).unwrap(),
            ),
        ])
        .unwrap();
        let program = WorkspaceProgramIndex::open(
            &workspace,
            [
                VerifiedArtifactOwner::new(first_scope, 27),
                VerifiedArtifactOwner::new(second_scope, 28),
            ],
        )
        .unwrap();

        assert!(matches!(
            WorkspaceEffectivePanicContracts::open(
                &workspace,
                &program,
                &ContractDocOverrides::default(),
            ),
            Err(WorkspaceEffectivePanicContractsError::RequirementAnchorNotIndexed { .. })
        ));
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
        let contracts = WorkspaceEffectivePanicContracts::open(
            &workspace,
            &program,
            &ContractDocOverrides::default(),
        )
        .unwrap();

        let generic = program.exact_callable(&scope, &generic).unwrap().id();
        let exact = program.exact_callable(&scope, &exact).unwrap().id();
        assert!(
            contracts
                .has_effective_panic_contract(&workspace, &generic)
                .unwrap()
        );
        assert!(
            contracts
                .has_effective_panic_contract(&workspace, &exact)
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
        let contracts = WorkspaceEffectivePanicContracts::open(
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
                .has_effective_panic_contract(&workspace, &first)
                .unwrap()
        );
        assert!(
            !contracts
                .has_effective_panic_contract(&workspace, &generic)
                .unwrap()
        );
        assert!(
            !contracts
                .has_effective_panic_contract(&workspace, &sibling)
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
        let contracts = WorkspaceEffectivePanicContracts::open(
            &workspace,
            &program,
            &ContractDocOverrides::default(),
        )
        .unwrap();

        let exact = program.exact_callable(&second_scope, &exact).unwrap().id();
        assert!(
            !contracts
                .has_effective_panic_contract(&workspace, &exact)
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
            WorkspaceEffectivePanicContracts::open(&workspace, &program, &overrides).unwrap();

        let exact = program.exact_callable(&scope, &exact).unwrap().id();
        assert!(
            !contracts
                .has_effective_panic_contract(&workspace, &exact)
                .unwrap()
        );
    }

    #[test]
    fn override_can_add_an_empty_panics_heading_and_is_snapshotted() {
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
            String::from("# Panics"),
        )])
        .unwrap();
        let contracts =
            WorkspaceEffectivePanicContracts::open(&workspace, &program, &overrides).unwrap();
        drop(overrides);

        let callable = program.exact_callable(&scope, &callable).unwrap().id();
        assert!(
            contracts
                .has_effective_panic_contract(&workspace, &callable)
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
                String::from("# Panics"),
            ),
        ])
        .unwrap();
        let contracts =
            WorkspaceEffectivePanicContracts::open(&workspace, &program, &overrides).unwrap();

        let exact = program.exact_callable(&scope, &exact).unwrap().id();
        assert!(
            contracts
                .has_effective_panic_contract(&workspace, &exact)
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
        let contracts = WorkspaceEffectivePanicContracts::open(
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
            WorkspaceEffectivePanicContracts::open(
                &replacement,
                &program,
                &ContractDocOverrides::default()
            ),
            Err(WorkspaceEffectivePanicContractsError::Program { .. })
        ));
        assert!(matches!(
            contracts.validate_workspace(&replacement),
            Err(WorkspaceEffectivePanicContractsError::WorkspaceMismatch)
        ));
        assert!(matches!(
            contracts.has_effective_panic_contract(&replacement, &replacement_callable),
            Err(WorkspaceEffectivePanicContractsError::WorkspaceMismatch)
        ));
    }

    #[test]
    fn both_panic_producer_tables_must_be_present_in_every_scope() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let key = callable_key(9, 1, None);
        for missing in [
            PanicContractFact::ID,
            super::super::contracts::PanicRequirement::ID,
        ] {
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
                WorkspaceEffectivePanicContracts::open(
                    &workspace,
                    &program,
                    &ContractDocOverrides::default()
                ),
                Err(WorkspaceEffectivePanicContractsError::MissingTable { ref schema, .. })
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
            WorkspaceEffectivePanicContracts::open(
                &workspace,
                &program,
                &ContractDocOverrides::default()
            ),
            Err(WorkspaceEffectivePanicContractsError::MissingOwner { .. })
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
            .facts::<PanicContractFact>()
            .unwrap()
            .pop()
            .unwrap();
        wrong.metadata.owner.as_mut().unwrap().schema =
            crate::analysis::facts::schema::SchemaId::new(PanicContractFact::ID).unwrap();
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
            Err(WorkspaceEffectivePanicContractsError::InvalidOwner { .. })
        ));

        let mut dangling = workspace
            .artifact(&scope)
            .unwrap()
            .facts::<PanicContractFact>()
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
            Err(WorkspaceEffectivePanicContractsError::InvalidOwner { .. })
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
            WorkspaceEffectivePanicContracts::open(
                &workspace,
                &program,
                &ContractDocOverrides::default()
            ),
            Err(WorkspaceEffectivePanicContractsError::DuplicateOwner { .. })
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
            let contracts = WorkspaceEffectivePanicContracts::open(
                &workspace,
                &program,
                &ContractDocOverrides::default(),
            )
            .unwrap();
            [first, second].map(|key| {
                contracts
                    .has_effective_panic_contract(
                        &workspace,
                        &program.exact_callable(&scope, &key).unwrap().id(),
                    )
                    .unwrap()
            })
        };

        assert_eq!(answers(&forward), answers(&reversed));
    }

    #[test]
    fn exact_raw_contract_wins_over_generic_raw_contract() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let generic = callable_key(24, 1, None);
        let exact = callable_key(24, 1, Some(241));
        let mut builder = ArtifactDbBuilder::new();
        for descriptor in registry.schemas().descriptors() {
            builder.declare_table(descriptor).unwrap();
        }
        let generic_owner = builder
            .insert_entity(&CallableEntity::new(
                generic,
                "crate::generic",
                false,
                false,
                false,
                false,
                vec![String::from("crate::generic")],
            ))
            .unwrap();
        let exact_owner = builder
            .insert_entity(&CallableEntity::new(
                exact,
                "crate::generic::<u8>",
                false,
                false,
                false,
                false,
                vec![String::from("crate::generic")],
            ))
            .unwrap();
        let generic_requirement = builder
            .insert_requirement(&PanicRequirement::new(
                generic,
                0,
                "generic only",
                "generic condition",
                None,
            ))
            .unwrap();
        let exact_requirement = builder
            .insert_requirement(&PanicRequirement::new(
                exact,
                0,
                "exact only",
                "exact condition",
                None,
            ))
            .unwrap();
        for (owner, requirement) in [
            (&generic_owner, &generic_requirement),
            (&exact_owner, &exact_requirement),
        ] {
            let metadata = FactMeta::new(PassId::new("test.panic.contract-index").unwrap())
                .with_owner(owner)
                .unwrap()
                .with_requirement(requirement)
                .unwrap();
            builder
                .insert_fact(&PanicContractFact::new(), metadata)
                .unwrap();
        }
        let artifact = builder.finalize(registry.schemas()).unwrap();
        let (scope, workspace, program) = workspace_and_program(&artifact, &registry, 24);
        let contracts = WorkspaceEffectivePanicContracts::open(
            &workspace,
            &program,
            &ContractDocOverrides::default(),
        )
        .unwrap();
        let exact = program.exact_callable(&scope, &exact).unwrap().id();
        let exact_fact = workspace
            .artifact(&scope)
            .unwrap()
            .facts::<PanicContractFact>()
            .unwrap()
            .into_iter()
            .find(|fact| {
                fact.metadata
                    .owner
                    .as_ref()
                    .is_some_and(|owner| owner.row == exact.entity().row())
            })
            .unwrap();
        let exact_fact =
            crate::analysis::facts::workspace::ScopedRowRef::new(scope, exact_fact.fact.reference);

        let contract = contracts
            .effective_panic_contract(&workspace, &exact)
            .unwrap()
            .unwrap();
        assert_eq!(contract.origin(), EffectivePanicContractOrigin::RawExact);
        assert_eq!(contract.declaration_owner(), &exact);
        assert_eq!(contract.raw_contract(), Some(&exact_fact));
        assert_eq!(contract.requirements()[0].name(), "exact only");
        assert_eq!(contract.requirements()[0].condition(), "exact condition");
    }

    #[test]
    fn fabricated_callable_row_is_rejected() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let key = callable_key(25, 1, None);
        let artifact = artifact(
            &registry,
            &[(key, "crate::callable", &["crate::callable"])],
            &[key],
        );
        let (scope, workspace, program) = workspace_and_program(&artifact, &registry, 25);
        let contracts = WorkspaceEffectivePanicContracts::open(
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
            ArtifactScopeId::for_in_memory(26, 0),
            valid.entity(),
        );

        for invalid in [&fabricated, &foreign_scope] {
            assert!(matches!(
                contracts.effective_panic_contract(&workspace, invalid),
                Err(WorkspaceEffectivePanicContractsError::InvalidCallableIdentity { .. })
            ));
        }
    }

    #[test]
    fn requirement_coverage_visits_scale_with_rows_not_prior_scopes() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let artifacts = (30_u64..38)
            .map(|stable_crate_id| {
                let owner = callable_key(stable_crate_id, 1, None);
                let artifact = artifact_with_requirements(
                    &registry,
                    owner,
                    &[PanicRequirement::new(owner, 0, "ready", "condition", None)],
                );
                (stable_crate_id, artifact)
            })
            .collect::<Vec<_>>();
        let scopes = artifacts
            .iter()
            .map(|(stable_crate_id, artifact)| {
                let scope = ArtifactScopeId::for_in_memory(*stable_crate_id, 0);
                (
                    scope,
                    ArtifactDbView::open(artifact, registry.schemas()).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let workspace = WorkspaceFactView::compose(scopes).unwrap();
        let owners = artifacts
            .iter()
            .zip(workspace.scopes())
            .map(|((stable_crate_id, _), scope)| {
                VerifiedArtifactOwner::new(scope.clone(), *stable_crate_id)
            })
            .collect::<Vec<_>>();
        let program = WorkspaceProgramIndex::open(&workspace, owners).unwrap();
        let contracts = WorkspaceEffectivePanicContracts::open(
            &workspace,
            &program,
            &ContractDocOverrides::default(),
        )
        .unwrap();

        assert_eq!(contracts.coverage_requirement_visits(), artifacts.len());
    }
}
