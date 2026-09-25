use serde::{Deserialize, Serialize};
use sniff_test_core::artifact::EffectKind;
use sniff_test_core::config::{EffectConfig, LintLevel};
use sniff_test_core::path_patterns::PathPatterns;
use strum::IntoStaticStr;

use self::visit::{BuiltinPanicInvocationPass, CompilerAssertPass};
#[cfg(test)]
use sniff_test_core::effects::concrete::{ConcreteEffect, ConcreteTermination};
use sniff_test_core::effects::visit::EffectPassRegistry;

pub mod visit;

pub struct Panic;

/// Stable operation names emitted by the built-in panic effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, IntoStaticStr)]
#[serde(rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum PanicOperation {
    BoundsCheck,
    Overflow,
    OverflowNegation,
    DivisionByZero,
    RemainderByZero,
    ResumedAfterReturn,
    ResumedAfterPanic,
    ResumedAfterDrop,
    MisalignedPointerDereference,
    NullPointerDereference,
    InvalidEnumConstruction,
    ConfiguredInvocation,
}

impl PanicOperation {
    const OPERATIONS: [Self; 11] = [
        Self::BoundsCheck,
        Self::Overflow,
        Self::OverflowNegation,
        Self::DivisionByZero,
        Self::RemainderByZero,
        Self::ResumedAfterReturn,
        Self::ResumedAfterPanic,
        Self::ResumedAfterDrop,
        Self::MisalignedPointerDereference,
        Self::NullPointerDereference,
        Self::InvalidEnumConstruction,
    ];

    #[must_use]
    pub fn as_str(self) -> &'static str {
        self.into()
    }
}

impl From<PanicOperation> for EffectKind {
    fn from(operation: PanicOperation) -> Self {
        Self::new(operation.as_str())
    }
}

impl sniff_test_core::effects::EffectSpec for Panic {
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
                PanicOperation::OPERATIONS.map(PanicOperation::as_str),
            )
            .build()
    }

    fn register_passes(registry: &mut EffectPassRegistry) {
        registry.register_mir_pass::<Self>(Box::new(CompilerAssertPass));
        registry.register_mir_pass::<Self>(Box::new(BuiltinPanicInvocationPass));
    }
}

#[cfg(test)]
pub type PanicEffect<'annotations> = ConcreteEffect<'annotations>;
#[cfg(test)]
pub type PanicTermination = ConcreteTermination;
