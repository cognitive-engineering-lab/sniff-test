use crate::artifact::{CallFact, DefinitionNamespaceIndex};
use crate::config::SafetyConfig;

use self::visit::SafetyThirPass;
use super::concrete::{
    ConcreteEffect, ConcreteEffectState, ConcreteTermination, InvocationSourceMatch,
};
use super::visit::EffectPassRegistry;

pub(crate) mod visit;

pub(crate) struct Safety;

impl super::Effect for Safety {
    type Config = SafetyConfig;

    const EFFECT_NAME: &'static str = "safety";
    const OBLIGATION: &'static str = "Safety";
    const JUSTIFICATION: &'static str = "SAFETY";
    const USES_ENCLOSING_SCOPE_MARKER: bool = true;

    fn register_passes(registry: &mut EffectPassRegistry) {
        registry.register_thir_pass::<Self>(Box::new(SafetyThirPass::default()));
    }

    fn invocation_source(
        _config: &Self::Config,
        call: &CallFact,
        _namespaces: &DefinitionNamespaceIndex,
    ) -> Option<InvocationSourceMatch> {
        (call.requires_explicit_context && !call.suppressed_by_compiler_context).then_some(
            InvocationSourceMatch {
                target: call.target.function_target().cloned(),
            },
        )
    }
}

pub(crate) type SafetyState = ConcreteEffectState;
pub(crate) type SafetyTermination = ConcreteTermination;
pub(crate) type SafetyEffect<'annotations> = ConcreteEffect<'annotations, Safety>;
