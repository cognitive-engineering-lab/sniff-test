use crate::config::SafetyConfig;

use self::visit::{SafetyInvocationPass, SafetyThirPass};
use super::concrete::{ConcreteEffect, ConcreteEffectState, ConcreteTermination};
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
        registry.register_mir_pass::<Self>(Box::new(SafetyInvocationPass));
    }
}

pub(crate) type SafetyState = ConcreteEffectState;
pub(crate) type SafetyTermination = ConcreteTermination;
pub(crate) type SafetyEffect<'annotations> = ConcreteEffect<'annotations, Safety>;
