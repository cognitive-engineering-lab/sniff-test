use crate::annotations::AnnotationDomain;
use crate::artifact::{
    CallFact, DefinitionNamespaceIndex, EffectFact, EffectFactKind, FunctionTargetFact,
};
use crate::compiler::{effect_passes::EffectPassRegistry, panic::CompilerAssertPass};
use crate::config::{PanicBoundaryPolicy, PanicConfig};

use super::concrete::{
    ConcreteEffect, ConcreteEffectState, ConcreteTermination, InvocationSourceMatch,
    OwnerProjection,
};

pub(crate) struct Panic;

impl super::Effect for Panic {
    type Config = PanicConfig;

    const EFFECT_NAME: &'static str = "panic";
    const DOMAIN: AnnotationDomain = AnnotationDomain::Panic;
    const OBLIGATION: &'static str = "Panics";
    const JUSTIFICATION: &'static str = "PANIC";

    fn register_passes(registry: &mut EffectPassRegistry) {
        registry.register_mir_pass(Box::new(CompilerAssertPass));
    }

    fn operation_source(effect: &EffectFact) -> Option<OwnerProjection> {
        matches!(effect.kind, EffectFactKind::CompilerAssert { .. })
            .then_some(OwnerProjection::Exact)
    }

    fn invocation_source(
        config: &Self::Config,
        call: &CallFact,
        namespaces: &DefinitionNamespaceIndex,
    ) -> Option<InvocationSourceMatch> {
        panic_sink_target(call, namespaces, config).map(|target| InvocationSourceMatch {
            target: Some(target.clone()),
        })
    }
}

pub(crate) type PanicState = ConcreteEffectState;
pub(crate) type PanicTermination = ConcreteTermination;
pub(crate) type PanicEffect<'annotations> = ConcreteEffect<'annotations, Panic>;

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
