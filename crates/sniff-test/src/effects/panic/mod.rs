use crate::config::PanicConfig;

use self::visit::{BuiltinPanicInvocationPass, CompilerAssertPass};
#[cfg(test)]
use super::concrete::{ConcreteEffect, ConcreteTermination};
use super::visit::EffectPassRegistry;

pub(crate) mod visit;

pub(crate) struct Panic;

impl super::EffectSpec for Panic {
    type Config = PanicConfig;

    const EFFECT_NAME: &'static str = "panic";
    const OBLIGATION: &'static str = "Panics";
    const JUSTIFICATION: &'static str = "PANIC";

    fn register_passes(registry: &mut EffectPassRegistry) {
        registry.register_mir_pass::<Self>(Box::new(CompilerAssertPass));
        registry.register_mir_pass::<Self>(Box::new(BuiltinPanicInvocationPass));
    }
}

#[cfg(test)]
pub(crate) type PanicEffect<'annotations> = ConcreteEffect<'annotations>;
#[cfg(test)]
pub(crate) type PanicTermination = ConcreteTermination;
