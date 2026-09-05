//! Syntax-level annotation indexing.
//!
//! This module records what the source says and where it was associated. It
//! deliberately does not decide whether an annotation starts, terminates, or
//! suppresses an effect; the concrete effect implementations make those
//! decisions independently and may reuse the same [`AnnotationId`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use effect_tracing::InvocationId;

use crate::artifact::{
    AnnotationFactKind, AnnotationProbingFact, AnnotationSatisfactionFact, AnnotationTargetFact,
    ArtifactFacts, CallId, ContractFact, ContractRequirementFact, DefinitionNamespaceIndex,
    EffectId, FunctionId, FunctionTargetFact, SourceRangeFact,
};
use crate::compiler::invocations::InvocationGraph;
use crate::config::MarkerProbing;
use crate::contracts::{
    ContractDocOverrides, ContractDocSummary, panic_contract_doc_summary_from_markdown,
    safety_contract_doc_summary_from_markdown,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct AnnotationId(usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum AnnotationDomain {
    Panic,
    Safety,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FunctionContractAnnotation {
    id: AnnotationId,
    owner: FunctionId,
    domain: AnnotationDomain,
    source_range: Option<SourceRangeFact>,
    requirements: Vec<ContractRequirementFact>,
}

impl FunctionContractAnnotation {
    #[must_use]
    pub(crate) const fn id(&self) -> AnnotationId {
        self.id
    }

    #[must_use]
    pub(crate) const fn owner(&self) -> FunctionId {
        self.owner
    }

    #[must_use]
    pub(crate) const fn domain(&self) -> AnnotationDomain {
        self.domain
    }

    #[must_use]
    pub(crate) fn requirements(&self) -> &[ContractRequirementFact] {
        &self.requirements
    }

    #[must_use]
    pub(crate) fn source_range(&self) -> Option<&SourceRangeFact> {
        self.source_range.as_ref()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SiteCommentAnnotation {
    id: AnnotationId,
    domain: AnnotationDomain,
    target: AnnotationTarget,
    source_range: Option<SourceRangeFact>,
    satisfactions: Vec<AnnotationSatisfactionFact>,
}

impl SiteCommentAnnotation {
    #[must_use]
    pub(crate) const fn id(&self) -> AnnotationId {
        self.id
    }

    #[must_use]
    pub(crate) const fn domain(&self) -> AnnotationDomain {
        self.domain
    }

    #[must_use]
    pub(crate) fn satisfactions(&self) -> &[AnnotationSatisfactionFact] {
        &self.satisfactions
    }

    #[must_use]
    pub(crate) fn has_justification(&self) -> bool {
        self.satisfactions
            .iter()
            .any(|satisfaction| !satisfaction.reason.trim().is_empty())
    }

    #[must_use]
    pub(crate) fn source_range(&self) -> Option<&SourceRangeFact> {
        self.source_range.as_ref()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum AnnotationTarget {
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
pub(crate) struct AnnotationIndex {
    contracts: Vec<FunctionContractAnnotation>,
    site_comments: Vec<SiteCommentAnnotation>,
}

impl AnnotationIndex {
    #[cfg(test)]
    pub(crate) fn from_artifact(
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
        )
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one syntax pass keeps annotation identities and ownership deterministic"
    )]
    pub(crate) fn from_artifact_with_overrides(
        artifact: &ArtifactFacts,
        graph: &InvocationGraph,
        namespaces: &DefinitionNamespaceIndex,
        overrides: &ContractDocOverrides,
        marker_probing: MarkerProbing,
    ) -> Result<Self, AnnotationIndexError> {
        let mut ids = BTreeMap::<String, AnnotationId>::new();
        let mut contracts = Vec::new();
        let mut site_comments = Vec::new();
        let override_markdown_by_definition = namespaces
            .iter()
            .filter_map(|(definition, candidates)| {
                overrides
                    .markdown_for_candidates(candidates)
                    .map(|markdown| (*definition, markdown))
            })
            .collect::<BTreeMap<_, _>>();

        for body in &artifact.functions {
            for marker in &body.markers {
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
                match marker.kind {
                    AnnotationFactKind::PanicContract | AnnotationFactKind::SafetyContract => {
                        let AnnotationTargetFact::Function(owner) = marker.target else {
                            return Err(AnnotationIndexError::new(
                                "function contract annotation has a non-function target",
                            ));
                        };
                        let annotation = FunctionContractAnnotation {
                            id,
                            owner,
                            domain: contract_domain(marker.kind),
                            source_range: marker.source_range.clone(),
                            requirements: marker.requirements.clone(),
                        };
                        if !contracts.contains(&annotation) {
                            contracts.push(annotation);
                        }
                    }
                    AnnotationFactKind::PanicJustification
                    | AnnotationFactKind::SafetyJustification => {
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
                            domain: justification_domain(marker.kind),
                            target,
                            source_range: marker.source_range.clone(),
                            satisfactions: marker.satisfactions.clone(),
                        };
                        if !site_comments.contains(&annotation) {
                            site_comments.push(annotation);
                        }
                    }
                }
            }
            if let Some(declaration) = &body.contract_declaration {
                push_target_contracts(&mut ids, &mut contracts, declaration);
            }
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
                    push_target_contracts(&mut ids, &mut contracts, target);
                }
            }
        }

        for (definition, markdown) in override_markdown_by_definition {
            contracts.retain(|contract| contract.owner.def_path_hash != definition);
            let source_range = artifact
                .functions
                .iter()
                .filter(|body| body.function.def_path_hash == definition)
                .min_by_key(|body| body.function)
                .and_then(|body| body.source_range.clone());
            let owner = FunctionId::generic(definition);
            push_override_contract_for_owner(
                &mut ids,
                &mut contracts,
                owner,
                source_range.clone(),
                panic_contract_doc_summary_from_markdown(markdown),
                AnnotationDomain::Panic,
            );
            push_override_contract_for_owner(
                &mut ids,
                &mut contracts,
                owner,
                source_range,
                safety_contract_doc_summary_from_markdown(markdown),
                AnnotationDomain::Safety,
            );
        }

        let original_comments = site_comments.clone();
        for comment in original_comments {
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
                if !site_comments.contains(&projected) {
                    site_comments.push(projected);
                }
            }
        }

        Ok(Self {
            contracts,
            site_comments,
        })
    }

    pub(crate) fn contracts(&self) -> impl ExactSizeIterator<Item = &FunctionContractAnnotation> {
        self.contracts.iter()
    }

    #[must_use]
    pub(crate) fn contract(&self, id: AnnotationId) -> Option<&FunctionContractAnnotation> {
        self.contracts.iter().find(|contract| contract.id == id)
    }

    #[must_use]
    pub(crate) fn site_comment(&self, id: AnnotationId) -> Option<&SiteCommentAnnotation> {
        self.site_comments.iter().find(|comment| comment.id == id)
    }

    pub(crate) fn function_contracts(
        &self,
        function: FunctionId,
        domain: AnnotationDomain,
    ) -> impl Iterator<Item = &FunctionContractAnnotation> {
        self.contracts.iter().filter(move |contract| {
            contract.owner.def_path_hash == function.def_path_hash && contract.domain == domain
        })
    }

    /// Selects the surface contract for a compiler-resolved implementation.
    ///
    /// A contract written on the implementation wins in that domain. When it
    /// is absent, the declared trait/interface contract is the fallback.
    pub(crate) fn effective_contract(
        &self,
        graph: &InvocationGraph,
        function: effect_tracing::FunctionId,
        domain: AnnotationDomain,
    ) -> Option<&FunctionContractAnnotation> {
        let stable_function = graph.stable_function(function);
        self.function_contracts(stable_function, domain)
            .next()
            .or_else(|| {
                graph
                    .contract_declaration(function)
                    .and_then(|declaration| self.function_contracts(declaration, domain).next())
            })
    }

    pub(crate) fn comments_at_raw_call(
        &self,
        invocation: InvocationId,
        call: CallId,
        domain: AnnotationDomain,
    ) -> impl Iterator<Item = &SiteCommentAnnotation> {
        self.site_comments.iter().filter(move |comment| {
            comment.domain == domain
                && comment.target == AnnotationTarget::Invocation { invocation, call }
        })
    }

    pub(crate) fn comments_at_effect(
        &self,
        owner: FunctionId,
        effect: EffectId,
        domain: AnnotationDomain,
    ) -> impl Iterator<Item = &SiteCommentAnnotation> {
        self.site_comments.iter().filter(move |comment| {
            comment.domain == domain && comment.target == AnnotationTarget::Effect { owner, effect }
        })
    }
}

fn push_override_contract_for_owner(
    ids: &mut BTreeMap<String, AnnotationId>,
    contracts: &mut Vec<FunctionContractAnnotation>,
    owner: FunctionId,
    source_range: Option<SourceRangeFact>,
    summary: ContractDocSummary,
    domain: AnnotationDomain,
) {
    if !summary.has_docs {
        return;
    }
    let identity = format!("override-contract:{domain:?}:{owner:?}");
    let next_id = AnnotationId(ids.len());
    let id = *ids.entry(identity).or_insert(next_id);
    let annotation = FunctionContractAnnotation {
        id,
        owner,
        domain,
        source_range,
        requirements: summary
            .requirements
            .into_iter()
            .map(|requirement| ContractRequirementFact {
                name: requirement.name,
                condition: requirement.condition,
                structural_path: requirement.path,
                source_range: None,
            })
            .collect(),
    };
    if !contracts.contains(&annotation) {
        contracts.push(annotation);
    }
}

fn push_call_contract(
    ids: &mut BTreeMap<String, AnnotationId>,
    contracts: &mut Vec<FunctionContractAnnotation>,
    target: &FunctionTargetFact,
    contract: &ContractFact,
    domain: AnnotationDomain,
) {
    let identity = format!(
        "call-contract:{domain:?}:{:?}:{:?}",
        target.function, contract.source_range
    );
    let next_id = AnnotationId(ids.len());
    let id = *ids.entry(identity).or_insert(next_id);
    let annotation = FunctionContractAnnotation {
        id,
        owner: target.function,
        domain,
        source_range: contract.source_range.clone(),
        requirements: contract.requirements.clone(),
    };
    if !contracts.contains(&annotation) {
        contracts.push(annotation);
    }
}

fn push_target_contracts(
    ids: &mut BTreeMap<String, AnnotationId>,
    contracts: &mut Vec<FunctionContractAnnotation>,
    target: &FunctionTargetFact,
) {
    if let Some(contract) = &target.contracts.panic {
        push_call_contract(ids, contracts, target, contract, AnnotationDomain::Panic);
    }
    if let Some(contract) = &target.contracts.safety {
        push_call_contract(ids, contracts, target, contract, AnnotationDomain::Safety);
    }
}

fn contract_domain(kind: AnnotationFactKind) -> AnnotationDomain {
    match kind {
        AnnotationFactKind::PanicContract => AnnotationDomain::Panic,
        AnnotationFactKind::SafetyContract => AnnotationDomain::Safety,
        AnnotationFactKind::PanicJustification | AnnotationFactKind::SafetyJustification => {
            unreachable!("justifications are not contracts")
        }
    }
}

fn justification_domain(kind: AnnotationFactKind) -> AnnotationDomain {
    match kind {
        AnnotationFactKind::PanicJustification => AnnotationDomain::Panic,
        AnnotationFactKind::SafetyJustification => AnnotationDomain::Safety,
        AnnotationFactKind::PanicContract | AnnotationFactKind::SafetyContract => {
            unreachable!("contracts are not justifications")
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AnnotationIndexError {
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
