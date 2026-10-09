//! Syntax-level annotation indexing.
//!
//! This module records what the source says and where it was associated. It
//! deliberately does not decide whether an annotation starts, terminates, or
//! suppresses an effect; the concrete effect implementations make those
//! decisions independently and may reuse the same [`AnnotationId`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AnnotationIndex {
    contracts: Vec<FunctionContractAnnotation>,
    contracts_by_definition:
        BTreeMap<crate::namespace::StableDefPathHash, BTreeMap<EffectKey, Vec<usize>>>,
    site_comments: Vec<SiteCommentAnnotation>,
    comments_by_target: BTreeMap<AnnotationTarget, BTreeMap<EffectKey, Vec<usize>>>,
}

/// Call-surface contracts are global even when report bodies are root scoped.
pub(crate) struct AnnotationWorkspaceIndex {
    call_contracts: Vec<SurfaceContractTemplate>,
    bodies_by_definition: BTreeMap<crate::namespace::StableDefPathHash, Vec<usize>>,
}

struct SurfaceContractTemplate {
    identity: String,
    owner: FunctionId,
    effect: EffectKey,
    source_range: Option<SourceRangeFact>,
    requirements: Vec<ContractRequirementFact>,
}

impl AnnotationWorkspaceIndex {
    pub(crate) fn new(artifact: &ArtifactFacts) -> Self {
        let mut call_contracts = Vec::<SurfaceContractTemplate>::new();
        let mut by_identity = BTreeMap::<String, Vec<usize>>::new();
        let mut bodies_by_definition = BTreeMap::<_, Vec<_>>::new();
        for (position, body) in artifact.functions.iter().enumerate() {
            bodies_by_definition
                .entry(body.function.def_path_hash)
                .or_default()
                .push(position);
            for call in &body.calls {
                let mut indexed_targets = BTreeSet::new();
                for target in [
                    call.target.function_target(),
                    call.declaration_target.as_ref(),
                ]
                .into_iter()
                .flatten()
                {
                    if !indexed_targets.insert(target.function) {
                        continue;
                    }
                    for effect_contract in &target.contracts.effects {
                        let contract = &effect_contract.contract;
                        let identity = format!(
                            "call-contract:{:?}:{:?}:{:?}",
                            effect_contract.effect, target.function, contract.source_range
                        );
                        let duplicate = by_identity.get(&identity).is_some_and(|positions| {
                            positions.iter().any(|&position| {
                                let existing = &call_contracts[position];
                                existing.owner == target.function
                                    && existing.effect == effect_contract.effect
                                    && existing.source_range == contract.source_range
                                    && existing.requirements == contract.requirements
                            })
                        });
                        if duplicate {
                            continue;
                        }
                        by_identity
                            .entry(identity.clone())
                            .or_default()
                            .push(call_contracts.len());
                        call_contracts.push(SurfaceContractTemplate {
                            identity,
                            owner: target.function,
                            effect: effect_contract.effect.clone(),
                            source_range: contract.source_range.clone(),
                            requirements: contract.requirements.clone(),
                        });
                    }
                }
            }
        }
        Self {
            call_contracts,
            bodies_by_definition,
        }
    }

    fn visible_body_positions(&self, graph: &InvocationGraph) -> Vec<usize> {
        let mut positions = graph
            .contract_definitions()
            .filter_map(|definition| self.bodies_by_definition.get(definition))
            .flatten()
            .copied()
            .collect::<Vec<_>>();
        // Annotation IDs and first-occurrence precedence follow artifact
        // order, not definition order. Include every instance of a visible
        // definition; only its site comments are restricted to reached bodies.
        positions.sort_unstable();
        positions
    }
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
    ) {
        if self.by_id.get(&id).is_some_and(|positions| {
            positions.iter().any(|&position| {
                let existing = &self.contracts[position];
                existing.owner == owner
                    && &existing.effect == effect
                    && existing.source_range.as_ref() == source_range
                    && existing.requirements == requirements
            })
        }) {
            return;
        }
        self.by_id.entry(id).or_default().push(self.contracts.len());
        self.contracts.push(FunctionContractAnnotation {
            id,
            owner,
            effect: effect.clone(),
            source_range: source_range.cloned(),
            requirements: requirements.to_vec(),
        });
    }

    fn remove_definition(&mut self, definition: crate::namespace::StableDefPathHash) {
        self.contracts
            .retain(|contract| contract.owner.def_path_hash != definition);
        self.by_id.clear();
        for (position, contract) in self.contracts.iter().enumerate() {
            self.by_id.entry(contract.id).or_default().push(position);
        }
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
        let workspace = AnnotationWorkspaceIndex::new(artifact);
        Self::from_workspace_index_with_overrides(
            artifact,
            graph,
            &workspace,
            namespaces,
            overrides,
            marker_probing,
            effects,
        )
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one syntax pass keeps annotation identities and ownership deterministic"
    )]
    pub(crate) fn from_workspace_index_with_overrides(
        artifact: &ArtifactFacts,
        graph: &InvocationGraph,
        workspace: &AnnotationWorkspaceIndex,
        namespaces: &DefinitionNamespaceIndex,
        overrides: &ContractDocOverrides,
        marker_probing: MarkerProbing,
        effects: &[EffectMetadata],
    ) -> Result<Self, AnnotationIndexError> {
        let mut ids = BTreeMap::<String, AnnotationId>::new();
        let mut contracts = ContractAccumulator::default();
        let mut site_comments = SiteCommentAccumulator::default();
        let override_markdown_by_definition = graph
            .contract_definitions()
            .filter_map(|definition| {
                overrides
                    .markdown_for_candidates(
                        namespaces.candidates(FunctionId::generic(*definition)),
                    )
                    .map(|markdown| (*definition, markdown))
            })
            .collect::<BTreeMap<_, _>>();

        for position in workspace.visible_body_positions(graph) {
            let body = &artifact.functions[position];
            let includes_body = graph.includes_body(body.function);
            for marker in &body.markers {
                if !includes_body && marker.kind.role != AnnotationRole::Contract {
                    continue;
                }
                let active = match marker_probing {
                    MarkerProbing::SourceCallsite => AnnotationProbingFact::SourceCallsite,
                    MarkerProbing::MacroDefinitionFirst => {
                        AnnotationProbingFact::MacroDefinitionFirst
                    }
                };
                if !marker.applicable_probing.contains(&active) {
                    continue;
                }
                let next_id = AnnotationId(ids.len());
                let id = *ids.entry(marker.identity.clone()).or_insert(next_id);
                match marker.kind.role {
                    AnnotationRole::Contract => {
                        let AnnotationTargetFact::Function(owner) = marker.target else {
                            return Err(AnnotationIndexError::new(
                                "function contract annotation has a non-function target",
                            ));
                        };
                        contracts.push(
                            id,
                            owner,
                            &marker.kind.effect,
                            marker.source_range.as_ref(),
                            &marker.requirements,
                        );
                    }
                    AnnotationRole::Justification => {
                        let target = match marker.target {
                            AnnotationTargetFact::Function(function) => {
                                AnnotationTarget::Function(function)
                            }
                            AnnotationTargetFact::Call(call) => {
                                let Some(invocation) =
                                    graph.invocation_for_raw_call(body.function, call)
                                else {
                                    // Syntax probing also sees structural raw edges such as
                                    // compiler assertions inside a marked statement. They remain
                                    // useful policy-neutral artifact evidence, but no concrete
                                    // effect can consume them as an invocation annotation.
                                    continue;
                                };
                                AnnotationTarget::Invocation { invocation, call }
                            }
                            AnnotationTargetFact::Effect(effect) => AnnotationTarget::Effect {
                                owner: body.function,
                                effect,
                            },
                        };
                        let annotation = SiteCommentAnnotation {
                            id,
                            effect: marker.kind.effect.clone(),
                            target,
                            source_range: marker.source_range.clone(),
                            satisfactions: marker.satisfactions.clone(),
                        };
                        site_comments.push(annotation);
                    }
                }
            }
            if let Some(declaration) = &body.contract_declaration {
                push_target_contracts(&mut ids, &mut contracts, declaration);
            }
        }

        // A declaration's contract can be serialized on a different call
        // projection from the one reached by this root. Index only this
        // surface metadata globally; site comments stay root scoped.
        for template in &workspace.call_contracts {
            let next_id = AnnotationId(ids.len());
            let id = *ids.entry(template.identity.clone()).or_insert(next_id);
            contracts.push(
                id,
                template.owner,
                &template.effect,
                template.source_range.as_ref(),
                &template.requirements,
            );
        }

        for (definition, markdown) in override_markdown_by_definition {
            contracts.remove_definition(definition);
            let source_range = workspace
                .bodies_by_definition
                .get(&definition)
                .into_iter()
                .flatten()
                .map(|&position| &artifact.functions[position])
                .min_by_key(|body| body.function)
                .and_then(|body| body.source_range.clone());
            let owner = FunctionId::generic(definition);
            for effect in effects {
                push_override_contract_for_owner(
                    &mut ids,
                    &mut contracts,
                    owner,
                    source_range.clone(),
                    contract_doc_summary_from_markdown(markdown, effect.obligation),
                    &effect.key,
                );
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
        let contracts = contracts.contracts;
        let mut contracts_by_definition = BTreeMap::<_, BTreeMap<_, Vec<_>>>::new();
        for (position, contract) in contracts.iter().enumerate() {
            contracts_by_definition
                .entry(contract.owner.def_path_hash)
                .or_default()
                .entry(contract.effect.clone())
                .or_default()
                .push(position);
        }
        Ok(Self {
            contracts,
            contracts_by_definition,
            site_comments,
            comments_by_target,
        })
    }

    #[must_use]
    pub fn contracts(&self) -> impl ExactSizeIterator<Item = &FunctionContractAnnotation> {
        self.contracts.iter()
    }

    #[must_use]
    pub fn contract(&self, id: AnnotationId) -> Option<&FunctionContractAnnotation> {
        self.contracts.iter().find(|contract| contract.id == id)
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
        self.contracts_by_definition
            .get(&function.def_path_hash)
            .and_then(|effects| effects.get(effect))
            .into_iter()
            .flatten()
            .map(|&position| &self.contracts[position])
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

fn push_override_contract_for_owner(
    ids: &mut BTreeMap<String, AnnotationId>,
    contracts: &mut ContractAccumulator,
    owner: FunctionId,
    source_range: Option<SourceRangeFact>,
    summary: ContractDocSummary,
    effect: &EffectKey,
) {
    if !summary.has_docs {
        return;
    }
    let identity = format!("override-contract:{effect:?}:{owner:?}");
    let next_id = AnnotationId(ids.len());
    let id = *ids.entry(identity).or_insert(next_id);
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
    contracts.push(id, owner, effect, source_range.as_ref(), &requirements);
}

fn push_call_contract(
    ids: &mut BTreeMap<String, AnnotationId>,
    contracts: &mut ContractAccumulator,
    target: &FunctionTargetFact,
    contract: &ContractFact,
    effect: &EffectKey,
) {
    let identity = format!(
        "call-contract:{effect:?}:{:?}:{:?}",
        target.function, contract.source_range
    );
    let next_id = AnnotationId(ids.len());
    let id = *ids.entry(identity).or_insert(next_id);
    contracts.push(
        id,
        target.function,
        effect,
        contract.source_range.as_ref(),
        &contract.requirements,
    );
}

fn push_target_contracts(
    ids: &mut BTreeMap<String, AnnotationId>,
    contracts: &mut ContractAccumulator,
    target: &FunctionTargetFact,
) {
    for effect_contract in &target.contracts.effects {
        push_call_contract(
            ids,
            contracts,
            target,
            &effect_contract.contract,
            &effect_contract.effect,
        );
    }
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

    use super::{AnnotationId, AnnotationWorkspaceIndex, ContractAccumulator};

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
    fn visible_annotations_keep_artifact_order_and_root_local_ids_in_both_probing_modes() {
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
        let workspace = AnnotationWorkspaceIndex::new(&artifact);
        let namespaces = artifact.definition_namespace_index();
        for (mode_index, mode) in [
            MarkerProbing::SourceCallsite,
            MarkerProbing::MacroDefinitionFirst,
        ]
        .into_iter()
        .enumerate()
        {
            for roots in [vec![owners[0], owners[1]], vec![owners[2]]] {
                let graph = InvocationGraph::from_artifact_roots(&artifact, &roots).unwrap();
                let annotations = AnnotationIndex::from_workspace_index_with_overrides(
                    &artifact,
                    &graph,
                    &workspace,
                    &namespaces,
                    &ContractDocOverrides::default(),
                    mode,
                    &[],
                )
                .unwrap();
                assert_eq!(
                    annotations
                        .contracts()
                        .map(super::FunctionContractAnnotation::owner)
                        .collect::<Vec<_>>(),
                    roots
                );
                for (id, contract) in annotations.contracts().enumerate() {
                    assert_eq!(contract.id(), AnnotationId(id));
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
        let index = AnnotationWorkspaceIndex::new(&artifact);
        assert_eq!(index.call_contracts.len(), 2);
        assert_eq!(index.call_contracts[0].requirements[0].name, "first");
        assert_eq!(index.call_contracts[1].requirements[0].name, "second");
        assert_eq!(
            index.call_contracts[0].identity,
            index.call_contracts[1].identity
        );
    }

    #[test]
    fn contract_accumulator_preserves_variants_and_updates_after_removal() {
        let first_owner = function(0);
        let second_owner = function(1);
        let effect = EffectKey::new("panic");
        let mut contracts = ContractAccumulator::default();
        contracts.push(
            AnnotationId(0),
            first_owner,
            &effect,
            None,
            &[requirement("first")],
        );
        contracts.push(
            AnnotationId(0),
            first_owner,
            &effect,
            None,
            &[requirement("first")],
        );
        contracts.push(
            AnnotationId(0),
            first_owner,
            &effect,
            None,
            &[requirement("second")],
        );
        contracts.push(
            AnnotationId(1),
            second_owner,
            &effect,
            None,
            &[requirement("third")],
        );
        assert_eq!(contracts.contracts.len(), 3);
        assert_eq!(contracts.contracts[0].requirements[0].name, "first");
        assert_eq!(contracts.contracts[1].requirements[0].name, "second");

        contracts.remove_definition(first_owner.def_path_hash);
        contracts.push(
            AnnotationId(1),
            second_owner,
            &effect,
            None,
            &[requirement("third")],
        );
        contracts.push(
            AnnotationId(1),
            second_owner,
            &effect,
            None,
            &[requirement("fourth")],
        );
        assert_eq!(contracts.contracts.len(), 2);
        assert_eq!(contracts.contracts[0].requirements[0].name, "third");
        assert_eq!(contracts.contracts[1].requirements[0].name, "fourth");
    }
}
