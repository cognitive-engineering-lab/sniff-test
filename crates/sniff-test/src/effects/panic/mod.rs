use crate::config::PanicConfig;

use self::visit::CompilerAssertPass;
use super::concrete::{ConcreteEffect, ConcreteEffectState, ConcreteTermination};
use super::visit::EffectPassRegistry;

pub(crate) mod visit;

pub(crate) struct Panic;

impl super::Effect for Panic {
    type Config = PanicConfig;

    const EFFECT_NAME: &'static str = "panic";
    const OBLIGATION: &'static str = "Panics";
    const JUSTIFICATION: &'static str = "PANIC";

    fn register_passes(registry: &mut EffectPassRegistry) {
        registry.register_mir_pass::<Self>(Box::new(CompilerAssertPass));
    }
}

pub(crate) type PanicState = ConcreteEffectState;
pub(crate) type PanicTermination = ConcreteTermination;
pub(crate) type PanicEffect<'annotations> = ConcreteEffect<'annotations, Panic>;
