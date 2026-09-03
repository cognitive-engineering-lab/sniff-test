use std::collections::{BTreeMap, BTreeSet};

use effect_tracing::{
    Effect, EffectSeed, FunctionId, InvocationId, Propagation, PropagationEdge, TraceCx, TraceSite,
};

use crate::annotations::{AnnotationDomain, AnnotationId, AnnotationIndex, SiteCommentAnnotation};
use crate::artifact::{
    ArtifactFacts, CallId, DefinitionNamespaceIndex, EffectFactKind, EffectId,
    FunctionId as StableFunctionId, SafetyOpKind, same_macro_provenance,
};
use crate::compiler::invocations::InvocationGraph;
use crate::config::SafetyConfig;

use super::{InvocationSourceBranch, ProbeError};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum SafetyOrigin {
    Invocation {
        invocation: InvocationId,
        call: CallId,
    },
    Operation {
        owner: StableFunctionId,
        effect: EffectId,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum SafetyKind {
    Invocation,
    Operation(SafetyOpKind),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct SafetyState {
    kind: SafetyKind,
    current_function: FunctionId,
    invocation_justification: Option<AnnotationId>,
}

impl SafetyState {
    #[must_use]
    pub(crate) const fn kind(self) -> SafetyKind {
        self.kind
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum SafetyTermination {
    Contract(AnnotationId),
    Justification(AnnotationId),
    TrustedBoundary,
    IgnoredBoundary,
}

pub(crate) struct SafetyEffect<'annotations> {
    annotations: &'annotations AnnotationIndex,
    graph: &'annotations InvocationGraph,
    seeds: Vec<EffectSeed<SafetyOrigin, SafetyState>>,
    trusted_functions: BTreeSet<FunctionId>,
    ignored_functions: BTreeSet<FunctionId>,
    invocation_sources: BTreeMap<InvocationId, Vec<InvocationSourceBranch>>,
}

impl<'annotations> SafetyEffect<'annotations> {
    #[allow(
        clippy::too_many_lines,
        reason = "safety probing remains effect-specific instead of introducing a compiler visitor registry"
    )]
    pub(crate) fn probe(
        artifact: &ArtifactFacts,
        graph: &'annotations InvocationGraph,
        annotations: &'annotations AnnotationIndex,
        namespaces: &DefinitionNamespaceIndex,
        config: &SafetyConfig,
    ) -> Result<Self, ProbeError> {
        let mut seeds = Vec::new();
        let mut trusted_functions = BTreeSet::new();
        let mut ignored_functions = BTreeSet::new();
        for body in &artifact.functions {
            let candidates = namespaces.candidates(body.function);
            if config.ignores_candidates(candidates) {
                ignored_functions.extend(graph.function_aliases(body.function));
                continue;
            }
            let owner = graph.function(body.function).ok_or_else(|| {
                ProbeError::new(format!(
                    "safety source owner {:?} is missing from the invocation graph",
                    body.function
                ))
            })?;
            if config.trusts_safety_boundary_candidates(candidates) {
                trusted_functions.extend(graph.function_aliases(body.function));
            }
            for effect in &body.effects {
                if let EffectFactKind::UnsafeOperation { kind } = effect.kind {
                    let owners = if body.function.instance_hash.is_none() {
                        graph
                            .function_aliases(body.function)
                            .filter(|alias| {
                                *alias == owner
                                    || !artifact
                                        .function_body(graph.stable_function(*alias))
                                        .is_some_and(|candidate| {
                                            candidate.effects.iter().any(|candidate| {
                                                same_unsafe_operation(candidate, effect)
                                            })
                                        })
                            })
                            .collect::<Vec<_>>()
                    } else {
                        vec![owner]
                    };
                    seeds.extend(owners.into_iter().map(|owner| {
                        EffectSeed::new(
                            SafetyOrigin::Operation {
                                owner: body.function,
                                effect: effect.id,
                            },
                            owner,
                            SafetyState {
                                kind: SafetyKind::Operation(kind),
                                current_function: owner,
                                invocation_justification: None,
                            },
                        )
                    }));
                }
            }
        }

        let mut invocation_sources = BTreeMap::<InvocationId, Vec<InvocationSourceBranch>>::new();
        for body in &artifact.functions {
            if config.ignores_candidates(namespaces.candidates(body.function)) {
                continue;
            }
            for call in &body.calls {
                if call.requires_unsafe
                    && !call.inside_builtin_unsafe
                    && let Some(invocation) = graph.invocation_for_raw_call(body.function, call.id)
                {
                    invocation_sources.entry(invocation).or_default().push(
                        InvocationSourceBranch::new(
                            call.clone(),
                            call.target.function_target().cloned(),
                        ),
                    );
                }
            }
        }
        for (&invocation, sources) in &invocation_sources {
            seeds.extend(sources.iter().map(|source| {
                EffectSeed::new(
                    SafetyOrigin::Invocation {
                        invocation,
                        call: source.edge().id,
                    },
                    graph.invocation(invocation).caller(),
                    SafetyState {
                        kind: SafetyKind::Invocation,
                        current_function: graph.invocation(invocation).caller(),
                        invocation_justification: None,
                    },
                )
            }));
        }
        Ok(Self {
            annotations,
            graph,
            seeds,
            trusted_functions,
            ignored_functions,
            invocation_sources,
        })
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) fn source_count(&self) -> usize {
        self.seeds.len()
    }

    #[must_use]
    pub(crate) fn is_opaque_function(&self, function: FunctionId) -> bool {
        self.is_trusted_function(function) || self.ignored_functions.contains(&function)
    }

    #[must_use]
    pub(crate) fn is_trusted_function(&self, function: FunctionId) -> bool {
        self.trusted_functions.contains(&function)
    }

    #[must_use]
    pub(crate) fn invocation_sources(&self, invocation: InvocationId) -> &[InvocationSourceBranch] {
        self.invocation_sources
            .get(&invocation)
            .map_or(&[], Vec::as_slice)
    }

    #[must_use]
    pub(crate) fn invocation_source(
        &self,
        invocation: InvocationId,
        call: CallId,
    ) -> Option<&InvocationSourceBranch> {
        self.invocation_sources(invocation)
            .iter()
            .find(|source| source.edge().id == call)
    }

    fn source_justification(&self, origin: SafetyOrigin) -> Option<AnnotationId> {
        match origin {
            SafetyOrigin::Invocation { invocation, call } => {
                self.raw_call_justification(invocation, call)
            }
            SafetyOrigin::Operation { owner, effect } => self
                .annotations
                .comments_at_effect(owner, effect, AnnotationDomain::Safety)
                .find(|comment| comment.has_justification())
                .map(SiteCommentAnnotation::id),
        }
    }

    fn invocation_justification(
        &self,
        invocation: InvocationId,
        target: FunctionId,
    ) -> Option<AnnotationId> {
        let mut calls = self.graph.raw_calls_reaching(invocation, target);
        let selected = self.raw_call_justification(invocation, calls.next()?)?;
        for call in calls {
            self.raw_call_justification(invocation, call)?;
        }
        Some(selected)
    }

    fn raw_call_justification(
        &self,
        invocation: InvocationId,
        call: CallId,
    ) -> Option<AnnotationId> {
        self.annotations
            .comments_at_raw_call(invocation, call, AnnotationDomain::Safety)
            .find(|comment| comment.has_justification())
            .map(SiteCommentAnnotation::id)
    }

    fn function_contract(&self, function: FunctionId) -> Option<AnnotationId> {
        self.annotations
            .effective_contract(self.graph, function, AnnotationDomain::Safety)
            .map(crate::annotations::FunctionContractAnnotation::id)
    }
}

impl Effect for SafetyEffect<'_> {
    type Origin = SafetyOrigin;
    type State = SafetyState;
    type Termination = SafetyTermination;

    fn sources(&self) -> impl Iterator<Item = EffectSeed<Self::Origin, Self::State>> + '_ {
        self.seeds.iter().cloned()
    }

    fn propagate(
        &self,
        cx: &TraceCx<'_>,
        state: &Self::State,
        edge: PropagationEdge,
    ) -> Propagation<Self::State> {
        let mut next = *state;
        next.invocation_justification = None;
        next.current_function = match edge {
            PropagationEdge::Invocation(invocation) => {
                next.invocation_justification =
                    self.invocation_justification(invocation, state.current_function);
                self.graph.invocation(invocation).caller()
            }
            PropagationEdge::TransparentBody(edge) => cx.graph().transparent_parent(edge),
        };
        Propagation::Follow(next)
    }

    fn terminate(
        &self,
        _cx: &TraceCx<'_>,
        state: &Self::State,
        site: TraceSite<'_, Self::Origin>,
    ) -> Option<Self::Termination> {
        match site {
            TraceSite::Source(origin) => self
                .source_justification(*origin)
                .map(SafetyTermination::Justification),
            TraceSite::Function(function) => self.function_contract(function).map_or_else(
                || {
                    if self.ignored_functions.contains(&function) {
                        Some(SafetyTermination::IgnoredBoundary)
                    } else {
                        self.trusted_functions
                            .contains(&function)
                            .then_some(SafetyTermination::TrustedBoundary)
                    }
                },
                |contract| Some(SafetyTermination::Contract(contract)),
            ),
            TraceSite::Invocation(_) => state
                .invocation_justification
                .map(SafetyTermination::Justification),
        }
    }
}

fn same_unsafe_operation(
    left: &crate::artifact::EffectFact,
    right: &crate::artifact::EffectFact,
) -> bool {
    left.kind == right.kind
        && left.safety_effect_group == right.safety_effect_group
        && left.source_range == right.source_range
        && left.expanded_range == right.expanded_range
        && same_macro_provenance(&left.macro_expansions, &right.macro_expansions)
}
