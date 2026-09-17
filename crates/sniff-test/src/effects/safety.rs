use std::collections::{BTreeMap, BTreeSet};

use effect_tracing::InvocationId;

use crate::annotations::{AnnotationDomain, AnnotationIndex};
use crate::artifact::{
    ArtifactFacts, CallId, DefinitionNamespaceIndex, EffectFactKind, EffectId,
    FunctionId as StableFunctionId, SafetyOpKind, same_macro_provenance,
};
use crate::compiler::invocations::InvocationGraph;
use crate::compiler::{effect_passes::EffectPassRegistry, safety::SafetyThirPass};
use crate::config::SafetyConfig;

use super::concrete::{
    ConcreteEffect, ConcreteEffectSeed, ConcreteEffectState, ConcreteTermination, JustificationSite,
};
use super::{InvocationSourceBranch, ProbeError};

pub(crate) struct Safety;

impl super::Effect for Safety {
    const EFFECT_NAME: &'static str = "safety";
    const OBLIGATION: &'static str = "Safety";
    const JUSTIFICATION: &'static str = "SAFETY";

    fn register_passes(registry: &mut EffectPassRegistry) {
        registry.register_thir_pass(Box::new(SafetyThirPass::default()));
    }
}

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

pub(crate) type SafetyState = ConcreteEffectState<SafetyKind>;
pub(crate) type SafetyTermination = ConcreteTermination;
pub(crate) type SafetyEffect<'annotations> = ConcreteEffect<'annotations, SafetyOrigin, SafetyKind>;

impl<'annotations> ConcreteEffect<'annotations, SafetyOrigin, SafetyKind> {
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
        let mut macro_ignored_sources = BTreeSet::new();
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
                    let origin = SafetyOrigin::Operation {
                        owner: body.function,
                        effect: effect.id,
                    };
                    if effect
                        .macro_expansions
                        .iter()
                        .any(|frame| config.ignores_path(&frame.display_path))
                    {
                        macro_ignored_sources.insert(origin);
                    }
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
                        ConcreteEffectSeed::new(
                            origin,
                            owner,
                            SafetyKind::Operation(kind),
                            JustificationSite::Effect {
                                owner: body.function,
                                effect: effect.id,
                            },
                        )
                    }));
                }
            }
        }

        let macro_ignored_invocations = graph
            .invocations()
            .filter(|invocation| {
                invocation
                    .macro_provenance()
                    .iter()
                    .any(|frame| config.ignores_path(&frame.display_path))
            })
            .map(crate::compiler::invocations::Invocation::id)
            .collect::<BTreeSet<_>>();

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
            for source in sources {
                let origin = SafetyOrigin::Invocation {
                    invocation,
                    call: source.edge().id,
                };
                if source
                    .edge()
                    .macro_expansions
                    .iter()
                    .any(|frame| config.ignores_path(&frame.display_path))
                {
                    macro_ignored_sources.insert(origin);
                }
                seeds.push(ConcreteEffectSeed::new(
                    origin,
                    graph.invocation(invocation).caller(),
                    SafetyKind::Invocation,
                    JustificationSite::Invocation {
                        invocation,
                        call: source.edge().id,
                    },
                ));
            }
        }
        Ok(Self::new(
            annotations,
            graph,
            AnnotationDomain::Safety,
            seeds,
            trusted_functions,
            ignored_functions,
            macro_ignored_sources,
            macro_ignored_invocations,
            invocation_sources,
        ))
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
