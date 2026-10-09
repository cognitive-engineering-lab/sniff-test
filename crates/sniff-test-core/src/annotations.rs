//! Syntax-level annotation indexing.
//!
//! This module records what the source says and where it was associated. It
//! deliberately does not decide whether an annotation starts, terminates, or
//! suppresses an effect; the concrete effect implementations make those
//! decisions independently and may reuse the same [`AnnotationId`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use crate::namespace::StableDefPathHash;

use crate::trace::InvocationId;

use crate::artifact::{
    AnnotationProbingFact, AnnotationRole, AnnotationSatisfactionFact, AnnotationTargetFact,
    ArtifactFacts, CallId, ContractFact, ContractRequirementFact, DefinitionNamespaceIndex,
    EffectId, EffectKey, FunctionId, FunctionTargetFact, SourceRangeFact,
};
use crate::compiler::invocations::InvocationGraph;
use crate::config::MarkerProbing;
use crate::contracts::{
    ContractDocOverrides, ContractDocSummary, contract_doc_summary_from_markdown,
};
use crate::effects::EffectMetadata;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AnnotationId(usize);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionContractAnnotation {
    id: AnnotationId,
    owner: FunctionId,
    effect: EffectKey,
    source_range: Option<SourceRangeFact>,
    requirements: Vec<ContractRequirementFact>,
}

impl FunctionContractAnnotation {
    #[must_use]
    pub const fn id(&self) -> AnnotationId {
        self.id
    }

    #[must_use]
    pub const fn owner(&self) -> FunctionId {
        self.owner
    }

    #[must_use]
    pub const fn effect(&self) -> &EffectKey {
        &self.effect
    }

    #[must_use]
    pub fn requirements(&self) -> &[ContractRequirementFact] {
        &self.requirements
    }

    #[must_use]
    pub fn source_range(&self) -> Option<&SourceRangeFact> {
        self.source_range.as_ref()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiteCommentAnnotation {
    id: AnnotationId,
    effect: EffectKey,
    target: AnnotationTarget,
    source_range: Option<SourceRangeFact>,
    satisfactions: Vec<AnnotationSatisfactionFact>,
}

impl SiteCommentAnnotation {
    #[must_use]
    pub const fn id(&self) -> AnnotationId {
        self.id
    }

    #[must_use]
    pub const fn effect(&self) -> &EffectKey {
        &self.effect
    }

    #[must_use]
    pub fn satisfactions(&self) -> &[AnnotationSatisfactionFact] {
        &self.satisfactions
    }

    #[must_use]
    pub fn has_justification(&self) -> bool {
        self.satisfactions
            .iter()
            .any(|satisfaction| !satisfaction.reason.trim().is_empty())
    }

    #[must_use]
    pub fn source_range(&self) -> Option<&SourceRangeFact> {
        self.source_range.as_ref()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AnnotationTarget {
    Function(FunctionId),
    Invocation {
        invocation: InvocationId,
        call: CallId,
    },
    Effect {
        owner: FunctionId,
        effect: EffectId,
    },
}

/// A root view of workspace-owned contracts and root-owned site comments.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AnnotationIndex {
    store: Arc<ContractStore>,
    body_contracts: ContractSelection,
    override_contracts: ContractSelection,
    excluded_global: BTreeSet<usize>,
    site_comments: Vec<SiteCommentAnnotation>,
    comments_by_target: BTreeMap<AnnotationTarget, BTreeMap<EffectKey, Vec<usize>>>,
}

/// Ordered record references, indexed without duplicating contract payloads.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ContractSelection {
    order: Vec<usize>,
    members: BTreeSet<usize>,
    by_definition: BTreeMap<StableDefPathHash, BTreeMap<EffectKey, Vec<usize>>>,
    by_id: BTreeMap<AnnotationId, Vec<usize>>,
}

impl ContractSelection {
    fn insert(&mut self, position: usize, records: &[FunctionContractAnnotation]) {
        if !self.members.insert(position) {
            return;
        }
        let record = &records[position];
        self.order.push(position);
        self.by_definition
            .entry(record.owner.def_path_hash)
            .or_default()
            .entry(record.effect.clone())
            .or_default()
            .push(position);
        self.by_id.entry(record.id).or_default().push(position);
    }

    fn function(&self, function: FunctionId, effect: &EffectKey) -> &[usize] {
        self.by_definition
            .get(&function.def_path_hash)
            .and_then(|effects| effects.get(effect))
            .map_or(&[], Vec::as_slice)
    }

    fn annotation(&self, id: AnnotationId) -> &[usize] {
        self.by_id.get(&id).map_or(&[], Vec::as_slice)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ContractStore {
    records: Vec<FunctionContractAnnotation>,
    global: ContractSelection,
}

/// Call-surface contracts are global even when report bodies are root scoped.
pub(crate) struct AnnotationWorkspaceIndex {
    store: Arc<ContractStore>,
    body_contracts: Vec<Result<Vec<usize>, AnnotationIndexError>>,
    marker_ids: Vec<Vec<AnnotationId>>,
    bodies_by_definition: BTreeMap<StableDefPathHash, Vec<usize>>,
    overrides: BTreeMap<StableDefPathHash, BTreeMap<EffectKey, usize>>,
    probing: AnnotationProbingFact,
}

impl AnnotationWorkspaceIndex {
    pub(crate) fn new(
        artifact: &ArtifactFacts,
        namespaces: &DefinitionNamespaceIndex,
        overrides: &ContractDocOverrides,
        marker_probing: MarkerProbing,
        effects: &[EffectMetadata],
    ) -> Self {
        let probing = match marker_probing {
            MarkerProbing::SourceCallsite => AnnotationProbingFact::SourceCallsite,
            MarkerProbing::MacroDefinitionFirst => AnnotationProbingFact::MacroDefinitionFirst,
        };
        let mut ids = BTreeMap::new();
        let mut contracts = ContractAccumulator::default();
        let mut bodies_by_definition = BTreeMap::<_, Vec<_>>::new();
        let mut body_contracts = Vec::new();
        let mut marker_ids = Vec::new();
        for (position, body) in artifact.functions.iter().enumerate() {
            bodies_by_definition
                .entry(body.function.def_path_hash)
                .or_default()
                .push(position);
            let mut positions = Vec::new();
            let mut invalid = false;
            let mut body_ids = Vec::new();
            for marker in &body.markers {
                let id = intern_identity(&mut ids, &marker.identity);
                body_ids.push(id);
                if marker.kind.role != AnnotationRole::Contract
                    || !marker.applicable_probing.contains(&probing)
                {
                    continue;
                }
                let AnnotationTargetFact::Function(owner) = marker.target else {
                    invalid = true;
                    continue;
                };
                positions.push(contracts.push(
                    id,
                    owner,
                    &marker.kind.effect,
                    marker.source_range.as_ref(),
                    &marker.requirements,
                ));
            }
            if let Some(declaration) = &body.contract_declaration {
                positions.extend(push_target_contracts(&mut ids, &mut contracts, declaration));
            }
            // Invalid annotations retain their former root-visible error boundary.
            body_contracts.push(if invalid {
                Err(AnnotationIndexError::new(
                    "function contract annotation has a non-function target",
                ))
            } else {
                Ok(positions)
            });
            marker_ids.push(body_ids);
        }
        let global = index_global_contracts(artifact, &mut ids, &mut contracts);
        let mut override_records = BTreeMap::new();
        for (definition, candidates) in namespaces.iter() {
            let Some(markdown) = overrides.markdown_for_candidates(candidates) else {
                continue;
            };
            let source_range = bodies_by_definition
                .get(definition)
                .into_iter()
                .flatten()
                .map(|&position| &artifact.functions[position])
                .min_by_key(|body| body.function)
                .and_then(|body| body.source_range.clone());
            let mut selected = BTreeMap::new();
            for effect in effects {
                if let Some(position) = push_override_contract_for_owner(
                    &mut ids,
                    &mut contracts,
                    FunctionId::generic(*definition),
                    source_range.as_ref(),
                    contract_doc_summary_from_markdown(markdown, effect.obligation),
                    &effect.key,
                ) {
                    selected.insert(effect.key.clone(), position);
                }
            }
            // An empty replacement still masks all original effects for this definition.
            override_records.insert(*definition, selected);
        }
        Self {
            store: Arc::new(ContractStore {
                records: contracts.contracts,
                global,
            }),
            body_contracts,
            marker_ids,
            bodies_by_definition,
            overrides: override_records,
            probing,
        }
    }

    fn visible_body_positions(&self, graph: &InvocationGraph) -> Vec<usize> {
        let mut positions = graph
            .contract_definitions()
            .filter_map(|definition| self.bodies_by_definition.get(definition))
            .flatten()
            .copied()
            .collect::<Vec<_>>();
        // Precedence follows artifact order, independently of workspace identity numbering.
        positions.sort_unstable();
        positions
    }
}

fn index_global_contracts(
    artifact: &ArtifactFacts,
    ids: &mut BTreeMap<String, AnnotationId>,
    contracts: &mut ContractAccumulator,
) -> ContractSelection {
    let mut global = ContractSelection::default();
    for body in &artifact.functions {
        for call in &body.calls {
            let mut indexed_targets = BTreeSet::new();
            for target in [
                call.target.function_target(),
                call.declaration_target.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                if indexed_targets.insert(target.function) {
                    for position in push_target_contracts(ids, contracts, target) {
                        global.insert(position, &contracts.contracts);
                    }
                }
            }
        }
    }
    global
}

fn intern_identity(ids: &mut BTreeMap<String, AnnotationId>, identity: &str) -> AnnotationId {
    if let Some(&id) = ids.get(identity) {
        return id;
    }
    let id = AnnotationId(ids.len());
    ids.insert(identity.to_owned(), id);
    id
}

#[derive(Default)]
struct SiteCommentAccumulator {
    comments: Vec<SiteCommentAnnotation>,
    by_identity_and_target: BTreeMap<(AnnotationId, AnnotationTarget), Vec<usize>>,
}

impl SiteCommentAccumulator {
    fn push(&mut self, comment: SiteCommentAnnotation) {
        let positions = self
            .by_identity_and_target
            .entry((comment.id, comment.target.clone()))
            .or_default();
        if positions
            .iter()
            .any(|&position| self.comments[position] == comment)
        {
            return;
        }
        positions.push(self.comments.len());
        self.comments.push(comment);
    }
}

#[derive(Default)]
struct ContractAccumulator {
    contracts: Vec<FunctionContractAnnotation>,
    by_id: BTreeMap<AnnotationId, Vec<usize>>,
}

impl ContractAccumulator {
    fn push(
        &mut self,
        id: AnnotationId,
        owner: FunctionId,
        effect: &EffectKey,
        source_range: Option<&SourceRangeFact>,
        requirements: &[ContractRequirementFact],
    ) -> usize {
        if let Some(position) = self.by_id.get(&id).and_then(|positions| {
            positions.iter().copied().find(|&position| {
                let existing = &self.contracts[position];
                existing.owner == owner
                    && &existing.effect == effect
                    && existing.source_range.as_ref() == source_range
                    && existing.requirements == requirements
            })
        }) {
            return position;
        }
        let position = self.contracts.len();
        self.by_id.entry(id).or_default().push(position);
        self.contracts.push(FunctionContractAnnotation {
            id,
            owner,
            effect: effect.clone(),
            source_range: source_range.cloned(),
            requirements: requirements.to_vec(),
        });
        position
    }
}

impl AnnotationIndex {
    #[cfg(test)]
    pub fn from_artifact(
        artifact: &ArtifactFacts,
        graph: &InvocationGraph,
    ) -> Result<Self, AnnotationIndexError> {
        let namespaces = artifact.definition_namespace_index();
        Self::from_artifact_with_overrides(
            artifact,
            graph,
            &namespaces,
            &ContractDocOverrides::default(),
            MarkerProbing::SourceCallsite,
            &crate::effects::selected_effects(&crate::effects::EffectSelection::default()),
        )
    }

    pub fn from_artifact_with_overrides(
        artifact: &ArtifactFacts,
        graph: &InvocationGraph,
        namespaces: &DefinitionNamespaceIndex,
        overrides: &ContractDocOverrides,
        marker_probing: MarkerProbing,
        effects: &[EffectMetadata],
    ) -> Result<Self, AnnotationIndexError> {
        let workspace =
            AnnotationWorkspaceIndex::new(artifact, namespaces, overrides, marker_probing, effects);
        Self::from_workspace_index(artifact, graph, &workspace, effects)
    }

    pub(crate) fn from_workspace_index(
        artifact: &ArtifactFacts,
        graph: &InvocationGraph,
        workspace: &AnnotationWorkspaceIndex,
        effects: &[EffectMetadata],
    ) -> Result<Self, AnnotationIndexError> {
        let store = &workspace.store;
        let mut body_contracts = ContractSelection::default();
        let mut override_contracts = ContractSelection::default();
        let mut excluded_global = BTreeSet::new();
        let mut site_comments = SiteCommentAccumulator::default();
        let overridden = graph
            .contract_definitions()
            .filter(|definition| workspace.overrides.contains_key(definition))
            .copied()
            .collect::<BTreeSet<_>>();
        for position in workspace.visible_body_positions(graph) {
            for &record in workspace.body_contracts[position]
                .as_ref()
                .map_err(Clone::clone)?
            {
                if !overridden.contains(&store.records[record].owner.def_path_hash) {
                    body_contracts.insert(record, &store.records);
                    if store.global.members.contains(&record) {
                        excluded_global.insert(record);
                    }
                }
            }
            let body = &artifact.functions[position];
            if !graph.includes_body(body.function) {
                continue;
            }
            for (marker, &id) in body.markers.iter().zip(&workspace.marker_ids[position]) {
                if marker.kind.role != AnnotationRole::Justification
                    || !marker.applicable_probing.contains(&workspace.probing)
                {
                    continue;
                }
                let target = match marker.target {
                    AnnotationTargetFact::Function(function) => {
                        AnnotationTarget::Function(function)
                    }
                    AnnotationTargetFact::Call(call) => {
                        let Some(invocation) = graph.invocation_for_raw_call(body.function, call)
                        else {
                            // Structural raw edges cannot consume invocation annotations.
                            continue;
                        };
                        AnnotationTarget::Invocation { invocation, call }
                    }
                    AnnotationTargetFact::Effect(effect) => AnnotationTarget::Effect {
                        owner: body.function,
                        effect,
                    },
                };
                site_comments.push(SiteCommentAnnotation {
                    id,
                    effect: marker.kind.effect.clone(),
                    target,
                    source_range: marker.source_range.clone(),
                    satisfactions: marker.satisfactions.clone(),
                });
            }
        }
        for definition in overridden {
            if let Some(buckets) = store.global.by_definition.get(&definition) {
                excluded_global.extend(buckets.values().flatten().copied());
            }
            for effect in effects {
                if let Some(&record) = workspace.overrides[&definition].get(&effect.key) {
                    override_contracts.insert(record, &store.records);
                }
            }
        }

        let original_count = site_comments.comments.len();
        for position in 0..original_count {
            let comment = site_comments.comments[position].clone();
            let AnnotationTarget::Invocation { invocation, call } = comment.target else {
                continue;
            };
            for alias in graph.invocation_aliases(invocation) {
                let Some(projected_call) = graph.projected_raw_call(invocation, call, alias) else {
                    continue;
                };
                let mut projected = comment.clone();
                projected.target = AnnotationTarget::Invocation {
                    invocation: alias,
                    call: projected_call,
                };
                site_comments.push(projected);
            }
        }

        let site_comments = site_comments.comments;
        let comments_by_target = index_site_comments(&site_comments);
        Ok(Self {
            store: Arc::clone(store),
            body_contracts,
            override_contracts,
            excluded_global,
            site_comments,
            comments_by_target,
        })
    }

    #[must_use]
    pub fn contracts(&self) -> impl ExactSizeIterator<Item = &FunctionContractAnnotation> {
        let remaining = self.body_contracts.order.len() + self.store.global.order.len()
            - self.excluded_global.len()
            + self.override_contracts.order.len();
        ExactContractIter {
            inner: self.active_records(
                &self.body_contracts.order,
                &self.store.global.order,
                &self.override_contracts.order,
            ),
            remaining,
        }
    }

    fn active_records<'a>(
        &'a self,
        body: &'a [usize],
        global: &'a [usize],
        overrides: &'a [usize],
    ) -> impl Iterator<Item = &'a FunctionContractAnnotation> {
        body.iter()
            .chain(
                global
                    .iter()
                    .filter(|position| !self.excluded_global.contains(position)),
            )
            .chain(overrides)
            .map(|&position| &self.store.records[position])
    }

    #[must_use]
    pub fn contract(&self, id: AnnotationId) -> Option<&FunctionContractAnnotation> {
        self.active_records(
            self.body_contracts.annotation(id),
            self.store.global.annotation(id),
            self.override_contracts.annotation(id),
        )
        .next()
    }

    #[must_use]
    pub fn site_comment(&self, id: AnnotationId) -> Option<&SiteCommentAnnotation> {
        self.site_comments.iter().find(|comment| comment.id == id)
    }

    pub fn function_contracts(
        &self,
        function: FunctionId,
        effect: &EffectKey,
    ) -> impl Iterator<Item = &FunctionContractAnnotation> {
        self.active_records(
            self.body_contracts.function(function, effect),
            self.store.global.function(function, effect),
            self.override_contracts.function(function, effect),
        )
    }

    /// Selects the surface contract for a compiler-resolved implementation.
    ///
    /// A contract written on the implementation wins in that domain. When it
    /// is absent, the declared trait/interface contract is the fallback.
    #[must_use]
    pub fn effective_contract(
        &self,
        graph: &InvocationGraph,
        function: crate::trace::FunctionId,
        effect: &EffectKey,
    ) -> Option<&FunctionContractAnnotation> {
        let stable_function = graph.stable_function(function);
        self.function_contracts(stable_function, effect)
            .next()
            .or_else(|| {
                graph
                    .contract_declaration(function)
                    .and_then(|declaration| self.function_contracts(declaration, effect).next())
            })
    }

    pub fn comments_at_raw_call(
        &self,
        invocation: InvocationId,
        call: CallId,
        effect: &EffectKey,
    ) -> impl Iterator<Item = &SiteCommentAnnotation> {
        self.comments_at_target(&AnnotationTarget::Invocation { invocation, call }, effect)
    }

    pub fn comments_at_effect(
        &self,
        owner: FunctionId,
        effect: EffectId,
        effect_key: &EffectKey,
    ) -> impl Iterator<Item = &SiteCommentAnnotation> {
        self.comments_at_target(&AnnotationTarget::Effect { owner, effect }, effect_key)
    }

    fn comments_at_target<'a>(
        &'a self,
        target: &AnnotationTarget,
        effect: &EffectKey,
    ) -> impl Iterator<Item = &'a SiteCommentAnnotation> + use<'a> {
        self.comments_by_target
            .get(target)
            .and_then(|effects| effects.get(effect))
            .into_iter()
            .flatten()
            .map(|&position| &self.site_comments[position])
    }
}

fn index_site_comments(
    comments: &[SiteCommentAnnotation],
) -> BTreeMap<AnnotationTarget, BTreeMap<EffectKey, Vec<usize>>> {
    let mut index = BTreeMap::<_, BTreeMap<_, Vec<_>>>::new();
    for (position, comment) in comments.iter().enumerate() {
        index
            .entry(comment.target.clone())
            .or_default()
            .entry(comment.effect.clone())
            .or_default()
            .push(position);
    }
    index
}

/// Filtering shared records must not require materializing a per-root vector.
struct ExactContractIter<I> {
    inner: I,
    remaining: usize,
}

impl<I: Iterator> Iterator for ExactContractIter<I> {
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        let next = self.inner.next();
        if next.is_some() {
            self.remaining -= 1;
        }
        next
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<I: Iterator> ExactSizeIterator for ExactContractIter<I> {}

fn push_override_contract_for_owner(
    ids: &mut BTreeMap<String, AnnotationId>,
    contracts: &mut ContractAccumulator,
    owner: FunctionId,
    source_range: Option<&SourceRangeFact>,
    summary: ContractDocSummary,
    effect: &EffectKey,
) -> Option<usize> {
    if !summary.has_docs {
        return None;
    }
    let identity = format!("override-contract:{effect:?}:{owner:?}");
    let id = intern_identity(ids, &identity);
    let requirements = summary
        .requirements
        .into_iter()
        .map(|requirement| ContractRequirementFact {
            name: requirement.name,
            condition: requirement.condition,
            structural_path: requirement.path,
            source_range: None,
        })
        .collect::<Vec<_>>();
    Some(contracts.push(id, owner, effect, source_range, &requirements))
}

fn push_call_contract(
    ids: &mut BTreeMap<String, AnnotationId>,
    contracts: &mut ContractAccumulator,
    target: &FunctionTargetFact,
    contract: &ContractFact,
    effect: &EffectKey,
) -> usize {
    let identity = format!(
        "call-contract:{effect:?}:{:?}:{:?}",
        target.function, contract.source_range
    );
    let id = intern_identity(ids, &identity);
    contracts.push(
        id,
        target.function,
        effect,
        contract.source_range.as_ref(),
        &contract.requirements,
    )
}

fn push_target_contracts(
    ids: &mut BTreeMap<String, AnnotationId>,
    contracts: &mut ContractAccumulator,
    target: &FunctionTargetFact,
) -> Vec<usize> {
    target
        .contracts
        .effects
        .iter()
        .map(|effect_contract| {
            push_call_contract(
                ids,
                contracts,
                target,
                &effect_contract.contract,
                &effect_contract.effect,
            )
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnnotationIndexError {
    message: String,
}

impl AnnotationIndexError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for AnnotationIndexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for AnnotationIndexError {}

#[cfg(test)]
mod tests {
    use crate::artifact::{
        ArtifactFacts, CallFact, CallId, CallKindFact, CallSiteId, CallTargetFact, ContractFact,
        ContractRequirementFact, EffectContractFact, EffectKey, FunctionAttributesFact,
        FunctionContractsFact, FunctionFact, FunctionFactProvenance, FunctionId,
        FunctionTargetFact,
    };
    use crate::namespace::StableDefPathHash;

    use super::{AnnotationId, AnnotationWorkspaceIndex};

    #[test]
    fn comment_indexes_preserve_variants_and_isolate_calls_and_effects() {
        use super::{
            AnnotationIndex, AnnotationTarget, SiteCommentAccumulator, SiteCommentAnnotation,
            index_site_comments,
        };
        use crate::artifact::{AnnotationSatisfactionFact, EffectId};
        use crate::trace::InvocationId;

        let invocation = InvocationId::from_index(0);
        let target = AnnotationTarget::Invocation {
            invocation,
            call: CallId::new(0),
        };
        let first = SiteCommentAnnotation {
            id: AnnotationId(7),
            effect: EffectKey::new("safety"),
            target: target.clone(),
            source_range: None,
            satisfactions: vec![AnnotationSatisfactionFact {
                requirement: None,
                reason: "first".to_owned(),
                structural_path: None,
            }],
        };
        let mut comments = SiteCommentAccumulator::default();
        comments.push(first.clone());
        comments.push(first.clone());
        let mut second = first.clone();
        second.satisfactions[0].reason = "second".to_owned();
        comments.push(second.clone());
        let mut sibling = first.clone();
        sibling.target = AnnotationTarget::Invocation {
            invocation,
            call: CallId::new(1),
        };
        comments.push(sibling.clone());
        let mut panic = first.clone();
        panic.effect = EffectKey::new("panic");
        comments.push(panic.clone());
        let mut operation = first.clone();
        operation.target = AnnotationTarget::Effect {
            owner: function(0),
            effect: EffectId::new(0),
        };
        comments.push(operation.clone());
        let site_comments = comments.comments;
        let index = AnnotationIndex {
            comments_by_target: index_site_comments(&site_comments),
            site_comments,
            ..AnnotationIndex::default()
        };
        let safety = EffectKey::new("safety");
        assert_eq!(index.site_comments.len(), 5);
        assert_eq!(
            index
                .comments_at_raw_call(invocation, CallId::new(0), &safety)
                .collect::<Vec<_>>(),
            vec![&first, &second]
        );
        assert_eq!(
            index
                .comments_at_raw_call(invocation, CallId::new(1), &safety)
                .collect::<Vec<_>>(),
            vec![&sibling]
        );
        assert_eq!(
            index
                .comments_at_raw_call(invocation, CallId::new(0), &panic.effect)
                .collect::<Vec<_>>(),
            vec![&panic]
        );
        assert_eq!(
            index
                .comments_at_effect(function(0), EffectId::new(0), &safety)
                .collect::<Vec<_>>(),
            vec![&operation]
        );
        assert_eq!(index.site_comment(AnnotationId(7)), Some(&first));
        assert!(
            index
                .comments_at_raw_call(InvocationId::from_index(1), CallId::new(0), &safety)
                .next()
                .is_none()
        );
        assert!(
            index
                .comments_at_effect(function(1), EffectId::new(0), &safety)
                .next()
                .is_none()
        );
        assert!(
            index
                .comments_at_raw_call(invocation, CallId::new(0), &EffectKey::new("allocation"))
                .next()
                .is_none()
        );
    }

    #[test]
    fn visible_annotations_keep_artifact_order_and_shared_ids_in_both_probing_modes() {
        use super::AnnotationIndex;
        use crate::artifact::{
            AnnotationFact, AnnotationFactKind, AnnotationProbingFact, AnnotationRole,
            AnnotationTargetFact, MarkerId,
        };
        use crate::compiler::invocations::InvocationGraph;
        use crate::config::MarkerProbing;
        use crate::contracts::ContractDocOverrides;

        let owners = [function(9), function(1), function(5)];
        let mut bodies = owners
            .iter()
            .map(|&owner| body(owner, Vec::new()))
            .collect::<Vec<_>>();
        for (position, body) in bodies.iter_mut().enumerate() {
            for (index, probing) in [
                AnnotationProbingFact::SourceCallsite,
                AnnotationProbingFact::MacroDefinitionFirst,
            ]
            .into_iter()
            .enumerate()
            {
                body.markers.push(AnnotationFact {
                    id: MarkerId::new(u32::try_from(index).unwrap()),
                    identity: format!("{position}-{index}"),
                    kind: AnnotationFactKind::new(
                        EffectKey::new("safety"),
                        AnnotationRole::Contract,
                    ),
                    source_range: None,
                    target: AnnotationTargetFact::Function(body.function),
                    applicable_probing: vec![probing],
                    satisfactions: Vec::new(),
                    requirements: vec![requirement(&format!("{position}-{index}"))],
                });
            }
        }
        let artifact = ArtifactFacts {
            functions: bodies,
            source_files: Vec::new(),
        };
        let namespaces = artifact.definition_namespace_index();
        for (mode_index, mode) in [
            MarkerProbing::SourceCallsite,
            MarkerProbing::MacroDefinitionFirst,
        ]
        .into_iter()
        .enumerate()
        {
            let workspace = AnnotationWorkspaceIndex::new(
                &artifact,
                &namespaces,
                &ContractDocOverrides::default(),
                mode,
                &[],
            );
            let all_graph = InvocationGraph::from_artifact_roots(&artifact, &owners).unwrap();
            let all = AnnotationIndex::from_workspace_index(&artifact, &all_graph, &workspace, &[])
                .unwrap();
            for roots in [vec![owners[0], owners[1]], vec![owners[2]]] {
                let graph = InvocationGraph::from_artifact_roots(&artifact, &roots).unwrap();
                let annotations =
                    AnnotationIndex::from_workspace_index(&artifact, &graph, &workspace, &[])
                        .unwrap();
                assert_eq!(
                    annotations
                        .contracts()
                        .map(super::FunctionContractAnnotation::owner)
                        .collect::<Vec<_>>(),
                    roots
                );
                assert!(std::sync::Arc::ptr_eq(&all.store, &annotations.store));
                for contract in annotations.contracts() {
                    let shared = all.contract(contract.id()).unwrap();
                    assert!(std::ptr::eq(shared, contract));
                    let position = owners
                        .iter()
                        .position(|&owner| owner == contract.owner())
                        .unwrap();
                    assert_eq!(
                        contract.requirements()[0].name,
                        format!("{position}-{mode_index}")
                    );
                }
            }
        }
    }

    #[test]
    fn comment_lookup_includes_projected_alias_with_different_raw_call_id() {
        use super::AnnotationIndex;
        use crate::artifact::{
            AnnotationFact, AnnotationFactKind, AnnotationProbingFact, AnnotationRole,
            AnnotationTargetFact, MarkerId, SourceFileId, SourceRangeFact,
        };
        use crate::compiler::invocations::InvocationGraph;

        let generic = function(0);
        let exact = FunctionId::exact(
            generic.def_path_hash,
            serde_json::from_str(&format!("\"{:032x}\"", 1)).unwrap(),
        );
        let callee = function(1);
        let mut defining = call(0, target(callee, "contract"));
        defining.source_range = Some(SourceRangeFact {
            file: SourceFileId::new("source"),
            byte_start: 10,
            byte_end: 20,
        });
        let mut projected = defining.clone();
        projected.id = CallId::new(1);
        projected.call_site = CallSiteId::new(99);
        let mut defining_body = body(generic, vec![defining]);
        defining_body.markers.push(AnnotationFact {
            id: MarkerId::new(0),
            identity: "shared".to_owned(),
            kind: AnnotationFactKind::new(EffectKey::new("safety"), AnnotationRole::Justification),
            source_range: None,
            target: AnnotationTargetFact::Call(CallId::new(0)),
            applicable_probing: vec![AnnotationProbingFact::SourceCallsite],
            satisfactions: Vec::new(),
            requirements: Vec::new(),
        });
        let artifact = ArtifactFacts {
            functions: vec![
                defining_body,
                body(exact, vec![call(0, target(callee, "contract")), projected]),
            ],
            source_files: Vec::new(),
        };
        let graph = InvocationGraph::from_artifact_roots(&artifact, &[generic, exact]).unwrap();
        let annotations = AnnotationIndex::from_artifact(&artifact, &graph).unwrap();
        let effect = EffectKey::new("safety");
        let source = graph
            .invocation_for_raw_call(generic, CallId::new(0))
            .unwrap();
        let alias = graph
            .invocation_for_raw_call(exact, CallId::new(1))
            .unwrap();
        let sibling = graph
            .invocation_for_raw_call(exact, CallId::new(0))
            .unwrap();
        let original = annotations
            .comments_at_raw_call(source, CallId::new(0), &effect)
            .next()
            .unwrap();
        let projected = annotations
            .comments_at_raw_call(alias, CallId::new(1), &effect)
            .collect::<Vec<_>>();
        assert_eq!(projected.len(), 1);
        assert_eq!(projected[0].id(), original.id());
        assert!(
            annotations
                .comments_at_raw_call(sibling, CallId::new(0), &effect)
                .next()
                .is_none()
        );
    }

    fn function(index: u64) -> FunctionId {
        let hash = format!("{index:016x}{:016x}", index + 100);
        FunctionId::generic(
            serde_json::from_str::<StableDefPathHash>(&format!("\"{hash}\""))
                .expect("valid stable hash"),
        )
    }

    fn requirement(name: &str) -> ContractRequirementFact {
        ContractRequirementFact {
            name: name.to_owned(),
            condition: String::new(),
            structural_path: Vec::new(),
            source_range: None,
        }
    }

    fn target(function: FunctionId, requirement_name: &str) -> FunctionTargetFact {
        FunctionTargetFact {
            function,
            display_path: String::from("sample::target"),
            attributes: FunctionAttributesFact {
                is_unsafe: false,
                is_exported: true,
                has_rust_body: false,
                is_foreign: false,
                namespace_candidates: vec![String::from("sample::target")],
            },
            contracts: FunctionContractsFact {
                effects: vec![EffectContractFact {
                    effect: EffectKey::new("panic"),
                    contract: ContractFact {
                        source_range: None,
                        requirements: vec![requirement(requirement_name)],
                    },
                }],
            },
        }
    }

    fn call(id: u32, target: FunctionTargetFact) -> CallFact {
        CallFact {
            id: CallId::new(id),
            call_site: CallSiteId::new(id),
            kind: CallKindFact::DirectCall,
            effect_group: None,
            invocation_effects: Vec::new(),
            suppressed_by_compiler_context: false,
            source_range: None,
            expanded_range: None,
            macro_expansions: Vec::new(),
            callee_range: None,
            indirect_kind: None,
            declaration_target: None,
            target: CallTargetFact::Function(target),
        }
    }

    fn body(owner: FunctionId, calls: Vec<CallFact>) -> FunctionFact {
        FunctionFact {
            function: owner,
            provenance: FunctionFactProvenance::DefiningArtifact,
            display_path: format!("sample::{owner:?}"),
            attributes: target(owner, "unused").attributes,
            contract_declaration: None,
            source_range: None,
            calls,
            effects: Vec::new(),
            markers: Vec::new(),
            unverified_marker_probes: Vec::new(),
        }
    }

    #[test]
    fn contract_probe_preserves_variants_and_only_selects_visible_instances() {
        use super::AnnotationIndex;
        use crate::compiler::invocations::InvocationGraph;
        use crate::config::EffectDocMatching;
        use crate::effects::obligation::{ObligationEffectPolicy, ObligationTracker};

        let root = function(0);
        let unrelated = function(1);
        let generic = function(2);
        let instances = (0..64)
            .map(|index| {
                FunctionId::exact(
                    generic.def_path_hash,
                    serde_json::from_str(&format!("\"{index:032x}\"")).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let make_target = |instance, name| {
            let mut value = target(instance, name);
            let mut safety = value.contracts.effects[0].clone();
            safety.effect = EffectKey::new("safety");
            value.contracts.effects.push(safety);
            value
        };
        let artifact = ArtifactFacts {
            functions: vec![
                body(
                    root,
                    vec![
                        call(0, make_target(instances[0], "first")),
                        call(1, make_target(instances[1], "first")),
                        call(2, make_target(instances[0], "second")),
                    ],
                ),
                body(
                    unrelated,
                    instances
                        .iter()
                        .enumerate()
                        .map(|(index, &instance)| {
                            call(
                                u32::try_from(index).unwrap(),
                                make_target(instance, "first"),
                            )
                        })
                        .collect(),
                ),
            ],
            source_files: Vec::new(),
        };
        let graph = InvocationGraph::from_artifact_roots(&artifact, &[root]).unwrap();
        let annotations = AnnotationIndex::from_artifact(&artifact, &graph).unwrap();
        let effects = [EffectKey::new("panic"), EffectKey::new("safety")];
        let tracker = ObligationTracker::probe(
            &graph,
            &annotations,
            EffectDocMatching::Exact,
            effects
                .iter()
                .map(|effect| ObligationEffectPolicy::new(effect.clone(), [], [])),
        );
        for effect in &effects {
            let variants = annotations
                .function_contracts(generic, effect)
                .collect::<Vec<_>>();
            assert_eq!(variants.len(), 65);
            assert_eq!(variants[0].requirements()[0].name, "first");
            assert_eq!(variants[2].requirements()[0].name, "second");
            assert_eq!(variants[0].id(), variants[2].id());
            // Both requirement variants of the selected ID survive in their
            // original order, while all other instance IDs remain unselected.
            assert_eq!(tracker.contract_count(effect), 2);
            let visible = graph.function(instances[0]).unwrap();
            assert_eq!(
                tracker
                    .boundary_contract(visible, effect)
                    .unwrap()
                    .annotation(),
                variants[0].id()
            );
            for (index, instance) in instances.iter().enumerate() {
                let function = graph.function(*instance).unwrap();
                let selected = tracker.boundary_contract(function, effect);
                assert_eq!(selected.is_some(), index < 2);
                for contract in tracker
                    .contracts()
                    .iter()
                    .filter(|contract| contract.id().annotation() == variants[0].id())
                {
                    assert_eq!(contract.applies_to(function), index < 2);
                }
            }
        }
        let ids = tracker
            .contracts()
            .iter()
            .map(|contract| contract.id().annotation())
            .collect::<Vec<_>>();
        let expected = annotations
            .contracts()
            .filter(|annotation| ids.contains(&annotation.id()))
            .map(super::FunctionContractAnnotation::id)
            .collect::<Vec<_>>();
        assert_eq!(ids, expected);
    }

    #[test]
    fn workspace_contracts_keep_first_occurrence_and_distinct_requirements() {
        let owner = function(0);
        let callee = function(1);
        let first = target(callee, "first");
        let second = target(callee, "second");
        let mut duplicate_at_one_call = call(0, first.clone());
        duplicate_at_one_call.declaration_target = Some(second.clone());
        let artifact = ArtifactFacts {
            functions: vec![FunctionFact {
                function: owner,
                provenance: FunctionFactProvenance::DefiningArtifact,
                display_path: String::from("sample::owner"),
                attributes: target(owner, "unused").attributes,
                contract_declaration: None,
                source_range: None,
                calls: vec![duplicate_at_one_call, call(1, first), call(2, second)],
                effects: Vec::new(),
                markers: Vec::new(),
                unverified_marker_probes: Vec::new(),
            }],
            source_files: Vec::new(),
        };
        let index = AnnotationWorkspaceIndex::new(
            &artifact,
            &artifact.definition_namespace_index(),
            &crate::contracts::ContractDocOverrides::default(),
            crate::config::MarkerProbing::SourceCallsite,
            &[],
        );
        let contracts = index
            .store
            .global
            .order
            .iter()
            .map(|&position| &index.store.records[position])
            .collect::<Vec<_>>();
        assert_eq!(contracts.len(), 2);
        assert_eq!(contracts[0].requirements[0].name, "first");
        assert_eq!(contracts[1].requirements[0].name, "second");
        assert_eq!(contracts[0].id, contracts[1].id);
    }

    #[test]
    fn root_views_share_global_variants_and_keep_body_precedence_and_comments_local() {
        use super::AnnotationIndex;
        use crate::artifact::{
            AnnotationFact, AnnotationFactKind, AnnotationProbingFact, AnnotationRole,
            AnnotationTargetFact, MarkerId,
        };
        use crate::compiler::invocations::InvocationGraph;
        use crate::config::MarkerProbing;
        use crate::contracts::ContractDocOverrides;

        let first = function(0);
        let second = function(1);
        let callee = function(2);
        let mut first_body = body(
            first,
            vec![
                call(0, target(callee, "global-first")),
                call(1, target(callee, "body-first")),
            ],
        );
        first_body.contract_declaration = Some(target(callee, "body-first"));
        first_body.markers.push(AnnotationFact {
            id: MarkerId::new(0),
            identity: "local-comment".to_owned(),
            kind: AnnotationFactKind::new(EffectKey::new("panic"), AnnotationRole::Justification),
            source_range: None,
            target: AnnotationTargetFact::Function(first),
            applicable_probing: vec![AnnotationProbingFact::SourceCallsite],
            satisfactions: Vec::new(),
            requirements: Vec::new(),
        });
        let artifact = ArtifactFacts {
            functions: vec![first_body, body(second, Vec::new())],
            source_files: Vec::new(),
        };
        let workspace = AnnotationWorkspaceIndex::new(
            &artifact,
            &artifact.definition_namespace_index(),
            &ContractDocOverrides::default(),
            MarkerProbing::SourceCallsite,
            &[],
        );
        let first_graph = InvocationGraph::from_artifact_roots(&artifact, &[first]).unwrap();
        let second_graph = InvocationGraph::from_artifact_roots(&artifact, &[second]).unwrap();
        let first_index =
            AnnotationIndex::from_workspace_index(&artifact, &first_graph, &workspace, &[])
                .unwrap();
        let second_index =
            AnnotationIndex::from_workspace_index(&artifact, &second_graph, &workspace, &[])
                .unwrap();
        assert!(std::sync::Arc::ptr_eq(
            &first_index.store,
            &second_index.store
        ));
        assert_eq!(first_index.site_comments.len(), 1);
        assert!(second_index.site_comments.is_empty());
        let effect = EffectKey::new("panic");
        for (index, expected) in [
            (&first_index, ["body-first", "global-first"]),
            (&second_index, ["global-first", "body-first"]),
        ] {
            let contracts = index
                .function_contracts(callee, &effect)
                .collect::<Vec<_>>();
            assert_eq!(
                contracts
                    .iter()
                    .map(|c| c.requirements()[0].name.as_str())
                    .collect::<Vec<_>>(),
                expected
            );
            assert_eq!(contracts[0].id(), contracts[1].id());
            assert!(std::ptr::eq(
                index.contract(contracts[0].id()).unwrap(),
                contracts[0]
            ));
            let mut iter = index.contracts();
            assert_eq!(iter.len(), 2);
            iter.next();
            assert_eq!(iter.len(), 1);
            iter.next();
            assert_eq!(iter.len(), 0);
            assert!(iter.next().is_none());
        }
        assert!(std::ptr::eq(
            first_index.contracts().next().unwrap(),
            second_index.contracts().nth(1).unwrap()
        ));
    }

    #[test]
    fn shared_overrides_mask_all_original_effects_only_in_visible_roots() {
        use super::AnnotationIndex;
        use crate::compiler::invocations::InvocationGraph;
        use crate::config::MarkerProbing;
        use crate::contracts::ContractDocOverrides;
        use crate::effects::{EffectSelection, selected_effects};

        let first = function(0);
        let second = function(1);
        let callee = function(2);
        let mut original = target(callee, "original");
        let mut safety = original.contracts.effects[0].clone();
        safety.effect = EffectKey::new("safety");
        original.contracts.effects.push(safety);
        let mut invocation = call(0, original.clone());
        invocation.target = CallTargetFact::OpaqueBoundary {
            description: "external declaration".to_owned(),
            target: Some(crate::artifact::OpaqueTargetFact::Function(original)),
        };
        let artifact = ArtifactFacts {
            functions: vec![body(first, vec![invocation]), body(second, Vec::new())],
            source_files: Vec::new(),
        };
        let effects = selected_effects(&EffectSelection::all());
        let graph = InvocationGraph::from_artifact_roots(&artifact, &[first]).unwrap();
        let other_graph = InvocationGraph::from_artifact_roots(&artifact, &[second]).unwrap();
        for markdown in ["# Safety\nReplacement obligation", "No contract sections"] {
            let overrides =
                ContractDocOverrides::new(vec![("sample::target".to_owned(), markdown.to_owned())])
                    .unwrap();
            let workspace = AnnotationWorkspaceIndex::new(
                &artifact,
                &artifact.definition_namespace_index(),
                &overrides,
                MarkerProbing::SourceCallsite,
                &effects,
            );
            for selected in [&effects[..], &effects[..0]] {
                let view =
                    AnnotationIndex::from_workspace_index(&artifact, &graph, &workspace, selected)
                        .unwrap();
                assert!(
                    view.function_contracts(callee, &EffectKey::new("panic"))
                        .next()
                        .is_none()
                );
                assert_eq!(
                    view.function_contracts(callee, &EffectKey::new("safety"))
                        .count(),
                    usize::from(!selected.is_empty() && markdown.starts_with("# Safety"))
                );
                assert_eq!(view.contracts().len(), view.contracts().count());
                let other = AnnotationIndex::from_workspace_index(
                    &artifact,
                    &other_graph,
                    &workspace,
                    selected,
                )
                .unwrap();
                assert_eq!(
                    other
                        .function_contracts(callee, &EffectKey::new("panic"))
                        .next()
                        .unwrap()
                        .requirements()[0]
                        .name,
                    "original"
                );
                assert_eq!(
                    other
                        .function_contracts(callee, &EffectKey::new("safety"))
                        .next()
                        .unwrap()
                        .requirements()[0]
                        .name,
                    "original"
                );
            }
        }
    }

    #[test]
    fn invalid_contract_is_reported_only_when_its_body_is_visible() {
        use super::AnnotationIndex;
        use crate::artifact::{
            AnnotationFact, AnnotationFactKind, AnnotationProbingFact, AnnotationRole,
            AnnotationTargetFact, MarkerId,
        };
        use crate::compiler::invocations::InvocationGraph;
        use crate::config::MarkerProbing;
        use crate::contracts::ContractDocOverrides;
        let invalid = function(0);
        let valid = function(1);
        let mut invalid_body = body(invalid, Vec::new());
        invalid_body.markers.push(AnnotationFact {
            id: MarkerId::new(0),
            identity: "invalid".to_owned(),
            kind: AnnotationFactKind::new(EffectKey::new("panic"), AnnotationRole::Contract),
            source_range: None,
            target: AnnotationTargetFact::Call(CallId::new(0)),
            applicable_probing: vec![AnnotationProbingFact::SourceCallsite],
            satisfactions: Vec::new(),
            requirements: Vec::new(),
        });
        let artifact = ArtifactFacts {
            functions: vec![invalid_body, body(valid, Vec::new())],
            source_files: Vec::new(),
        };
        let workspace = AnnotationWorkspaceIndex::new(
            &artifact,
            &artifact.definition_namespace_index(),
            &ContractDocOverrides::default(),
            MarkerProbing::SourceCallsite,
            &[],
        );
        for (root, succeeds) in [(valid, true), (invalid, false)] {
            let graph = InvocationGraph::from_artifact_roots(&artifact, &[root]).unwrap();
            assert_eq!(
                AnnotationIndex::from_workspace_index(&artifact, &graph, &workspace, &[]).is_ok(),
                succeeds
            );
        }
    }
}
