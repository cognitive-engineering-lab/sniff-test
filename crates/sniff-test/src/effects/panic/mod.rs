use crate::config::{EffectConfig, LintLevel};
use crate::path_patterns::PathPatterns;

use self::visit::{BuiltinPanicInvocationPass, CompilerAssertPass};
#[cfg(test)]
use super::concrete::{ConcreteEffect, ConcreteTermination};
use super::visit::EffectPassRegistry;

pub(crate) mod visit;

pub(crate) struct Panic;

impl super::EffectSpec for Panic {
    const EFFECT_NAME: &'static str = "panic";
    const OBLIGATION: &'static str = "Panics";
    const JUSTIFICATION: &'static str = "PANIC";

    fn default_config() -> EffectConfig {
        EffectConfig::builder()
            .ignored_namespaces(
                PathPatterns::new(vec![String::from(
                    "core::ub_checks::assert_unsafe_precondition",
                )])
                .expect("built-in panic ignore is valid"),
            )
            .operations(
                LintLevel::Warn,
                [
                    "bounds-check",
                    "overflow",
                    "overflow-negation",
                    "division-by-zero",
                    "remainder-by-zero",
                    "resumed-after-return",
                    "resumed-after-panic",
                    "resumed-after-drop",
                    "misaligned-pointer-dereference",
                    "null-pointer-dereference",
                    "invalid-enum-construction",
                ],
            )
            .build()
    }

    fn register_passes(registry: &mut EffectPassRegistry) {
        registry.register_mir_pass::<Self>(Box::new(CompilerAssertPass));
        registry.register_mir_pass::<Self>(Box::new(BuiltinPanicInvocationPass));
    }
}

#[cfg(test)]
pub(crate) type PanicEffect<'annotations> = ConcreteEffect<'annotations>;
#[cfg(test)]
pub(crate) type PanicTermination = ConcreteTermination;
