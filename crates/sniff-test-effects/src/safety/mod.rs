use serde::{Deserialize, Serialize};
use sniff_test_core::artifact::EffectKind;
use sniff_test_core::config::{EffectConfig, LintLevel};
use strum::IntoStaticStr;

use self::visit::{SafetyInvocationPass, SafetyThirPass};
#[cfg(test)]
use sniff_test_core::effects::concrete::{ConcreteEffect, ConcreteTermination};
use sniff_test_core::effects::visit::EffectPassRegistry;

pub mod visit;

pub struct Safety;

/// Stable operation names emitted by the built-in safety effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, IntoStaticStr)]
#[serde(rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum SafetyOperation {
    RawPointerDereference,
    MutableStaticAccess,
    ExternStaticAccess,
    UnionFieldAccess,
    UnsafeFieldAccess,
    LayoutConstrainedTypeInitialization,
    UnsafeFieldInitialization,
    LayoutConstrainedFieldMutation,
    LayoutConstrainedFieldBorrow,
    InlineAssembly,
    UnsafeBinderCast,
    UnsafeCall,
}

impl SafetyOperation {
    const OPERATIONS: [Self; 11] = [
        Self::RawPointerDereference,
        Self::MutableStaticAccess,
        Self::ExternStaticAccess,
        Self::UnionFieldAccess,
        Self::UnsafeFieldAccess,
        Self::LayoutConstrainedTypeInitialization,
        Self::UnsafeFieldInitialization,
        Self::LayoutConstrainedFieldMutation,
        Self::LayoutConstrainedFieldBorrow,
        Self::InlineAssembly,
        Self::UnsafeBinderCast,
    ];

    #[must_use]
    pub fn as_str(self) -> &'static str {
        self.into()
    }
}

impl From<SafetyOperation> for EffectKind {
    fn from(operation: SafetyOperation) -> Self {
        Self::new(operation.as_str())
    }
}

impl sniff_test_core::effects::EffectSpec for Safety {
    const EFFECT_NAME: &'static str = "safety";
    const OBLIGATION: &'static str = "Safety";
    const JUSTIFICATION: &'static str = "SAFETY";
    const USES_ENCLOSING_SCOPE_MARKER: bool = true;

    fn default_config() -> EffectConfig {
        EffectConfig::builder()
            .operations(
                LintLevel::Warn,
                SafetyOperation::OPERATIONS.map(SafetyOperation::as_str),
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
