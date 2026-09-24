use sniff_test_core::config::{EffectConfig, LintLevel};

use self::visit::{SafetyInvocationPass, SafetyThirPass};
#[cfg(test)]
use sniff_test_core::effects::concrete::{ConcreteEffect, ConcreteTermination};
use sniff_test_core::effects::visit::EffectPassRegistry;

pub mod visit;

pub struct Safety;

impl sniff_test_core::effects::EffectSpec for Safety {
    const EFFECT_NAME: &'static str = "safety";
    const OBLIGATION: &'static str = "Safety";
    const JUSTIFICATION: &'static str = "SAFETY";
    const USES_ENCLOSING_SCOPE_MARKER: bool = true;

    fn default_config() -> EffectConfig {
        EffectConfig::builder()
            .operations(
                LintLevel::Warn,
                [
                    "raw-pointer-dereference",
                    "mutable-static-access",
                    "extern-static-access",
                    "union-field-access",
                    "unsafe-field-access",
                    "layout-constrained-type-initialization",
                    "unsafe-field-initialization",
                    "layout-constrained-field-mutation",
                    "layout-constrained-field-borrow",
                    "inline-assembly",
                    "unsafe-binder-cast",
                ],
            )
            .build()
    }

    fn register_passes(registry: &mut EffectPassRegistry) {
        registry.register_thir_pass::<Self>(Box::new(SafetyThirPass::default()));
        registry.register_mir_pass::<Self>(Box::new(SafetyInvocationPass));
    }
}

#[cfg(test)]
pub type SafetyEffect<'annotations> = ConcreteEffect<'annotations>;
#[cfg(test)]
pub type SafetyTermination = ConcreteTermination;
