use std::collections::{BTreeMap, BTreeSet};

use effect_tracing::InvocationId;

use crate::annotations::{AnnotationDomain, AnnotationIndex};
use crate::artifact::{
    ArtifactFacts, CallFact, CallId, CompilerAssertKind, DefinitionNamespaceIndex, EffectFactKind,
    EffectId, FunctionId as StableFunctionId, FunctionTargetFact,
};
use crate::compiler::invocations::InvocationGraph;
use crate::compiler::{effect_passes::EffectPassRegistry, panic::CompilerAssertPass};
use crate::config::{PanicBoundaryPolicy, PanicConfig};

use super::concrete::{
    ConcreteEffect, ConcreteEffectSeed, ConcreteEffectState, ConcreteTermination, JustificationSite,
};
use super::{InvocationSourceBranch, ProbeError};

pub(crate) struct Panic;

impl super::Effect for Panic {
    const EFFECT_NAME: &'static str = "panic";
    const OBLIGATION: &'static str = "Panics";
    const JUSTIFICATION: &'static str = "PANIC";

    fn register_passes(registry: &mut EffectPassRegistry) {
        registry.register_mir_pass(Box::new(CompilerAssertPass));
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum PanicOrigin {
    Invocation {
        invocation: InvocationId,
        call: CallId,
    },
    CompilerAssert {
        owner: StableFunctionId,
        effect: EffectId,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum PanicKind {
    Invocation,
    CompilerAssert(CompilerAssertKind),
}

pub(crate) type PanicState = ConcreteEffectState<PanicKind>;
pub(crate) type PanicTermination = ConcreteTermination;
pub(crate) type PanicEffect<'annotations> = ConcreteEffect<'annotations, PanicOrigin, PanicKind>;

impl<'annotations> ConcreteEffect<'annotations, PanicOrigin, PanicKind> {
    #[allow(
        clippy::too_many_lines,
        reason = "panic probing remains effect-specific instead of introducing a compiler visitor registry"
    )]
    pub(crate) fn probe(
        artifact: &ArtifactFacts,
        graph: &'annotations InvocationGraph,
        annotations: &'annotations AnnotationIndex,
        namespaces: &DefinitionNamespaceIndex,
        config: &PanicConfig,
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
                    "panic source owner {:?} is missing from the invocation graph",
                    body.function
                ))
            })?;
            if config.panic_boundary_policy_candidates(candidates)
                == PanicBoundaryPolicy::TrustedBoundary
            {
                trusted_functions.extend(graph.function_aliases(body.function));
            }
            for effect in &body.effects {
                if let EffectFactKind::CompilerAssert { kind } = effect.kind {
                    let origin = PanicOrigin::CompilerAssert {
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
                    seeds.push(ConcreteEffectSeed::new(
                        origin,
                        owner,
                        PanicKind::CompilerAssert(kind),
                        JustificationSite::Effect {
                            owner: body.function,
                            effect: effect.id,
                        },
                    ));
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
                let Some(target) = panic_sink_target(call, namespaces, config) else {
                    continue;
                };
                if let Some(invocation) = graph.invocation_for_raw_call(body.function, call.id) {
                    invocation_sources.entry(invocation).or_default().push(
                        InvocationSourceBranch::new(call.clone(), Some(target.clone())),
                    );
                }
            }
        }
        for (&invocation, sources) in &invocation_sources {
            for source in sources {
                let origin = PanicOrigin::Invocation {
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
                    PanicKind::Invocation,
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
            AnnotationDomain::Panic,
            seeds,
            trusted_functions,
            ignored_functions,
            macro_ignored_sources,
            macro_ignored_invocations,
            invocation_sources,
        ))
    }
}

fn panic_sink_target<'call>(
    call: &'call CallFact,
    namespaces: &DefinitionNamespaceIndex,
    config: &PanicConfig,
) -> Option<&'call FunctionTargetFact> {
    call.target
        .function_target()
        .filter(|target| {
            config.panic_boundary_policy_candidates(namespaces.candidates(target.function))
                == PanicBoundaryPolicy::PanicSink
        })
        .or_else(|| {
            call.declaration_target.as_ref().filter(|target| {
                config.panic_boundary_policy_candidates(namespaces.candidates(target.function))
                    == PanicBoundaryPolicy::PanicSink
            })
        })
}
