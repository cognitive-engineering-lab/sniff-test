use crate::annotations::AnnotationDomain;
use crate::artifact::{CallFact, DefinitionNamespaceIndex, EffectKey};
use crate::compiler::{effect_passes::EffectPassRegistry, safety::SafetyThirPass};
use crate::config::SafetyConfig;

use super::concrete::{
    ConcreteEffect, ConcreteEffectState, ConcreteTermination, InvocationSourceMatch,
};

pub(crate) struct Safety;

impl super::Effect for Safety {
    type Config = SafetyConfig;

    const EFFECT_KEY: &'static str = EffectKey::SAFETY;
    const EFFECT_NAME: &'static str = "safety";
    const DOMAIN: AnnotationDomain = AnnotationDomain::Safety;
    const OBLIGATION: &'static str = "Safety";
    const JUSTIFICATION: &'static str = "SAFETY";

    fn register_passes(registry: &mut EffectPassRegistry) {
        registry.register_thir_pass::<Self>(Box::new(SafetyThirPass::default()));
    }

    fn invocation_source(
        _config: &Self::Config,
        call: &CallFact,
        _namespaces: &DefinitionNamespaceIndex,
    ) -> Option<InvocationSourceMatch> {
        (call.requires_unsafe && !call.inside_builtin_unsafe).then_some(InvocationSourceMatch {
            target: call.target.function_target().cloned(),
        })
    }
}

pub(crate) type SafetyState = ConcreteEffectState;
pub(crate) type SafetyTermination = ConcreteTermination;
pub(crate) type SafetyEffect<'annotations> = ConcreteEffect<'annotations, Safety>;
