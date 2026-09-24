pub mod concrete;
pub mod obligation;
pub mod trust;
pub mod visit;

use std::collections::BTreeSet;
use std::fmt;
use std::marker::PhantomData;

#[cfg(test)]
use crate::artifact::{AnnotationFactKind, AnnotationRole};
use crate::artifact::{CallFact, EffectKey, FunctionTargetFact};
use serde::{Deserialize, Serialize};

use crate::config::EffectConfig;

use self::visit::EffectPassRegistry;

#[cfg(test)]
pub mod panic {
    use crate::config::{EffectConfig, LintLevel};
    use crate::path_patterns::PathPatterns;

    pub struct Panic;
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

        fn register_passes(_: &mut super::visit::EffectPassRegistry) {}
    }
    pub type PanicEffect<'a> = super::concrete::ConcreteEffect<'a>;
    pub type PanicTermination = super::concrete::ConcreteTermination;
}

#[cfg(test)]
pub mod safety {
    use crate::config::{EffectConfig, LintLevel};

    pub struct Safety;
    struct TestSafetyThirPass;

    impl super::visit::ThirEffectPass for TestSafetyThirPass {
        fn check_body<'tcx>(
            &mut self,
            _: rustc_middle::ty::TyCtxt<'tcx>,
            _: rustc_hir::def_id::LocalDefId,
            _: &rustc_middle::thir::Thir<'tcx>,
            _: rustc_middle::thir::ExprId,
        ) {
        }
    }
    impl super::EffectSpec for Safety {
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

        fn register_passes(registry: &mut super::visit::EffectPassRegistry) {
            registry.register_thir_pass::<Self>(Box::new(TestSafetyThirPass));
        }
    }
    pub type SafetyEffect<'a> = super::concrete::ConcreteEffect<'a>;
    pub type SafetyTermination = super::concrete::ConcreteTermination;

    pub mod visit {
        #[must_use]
        pub const fn compiler_call_requires_explicit_context(
            signature_requires_explicit_context: bool,
            safe_target_features: bool,
            target_features_are_safe: bool,
        ) -> bool {
            (signature_requires_explicit_context && !safe_target_features)
                || !target_features_are_safe
        }
    }
}

#[cfg(test)]
#[must_use]
pub fn selected_effect_objects<'config>(
    selection: &EffectSelection,
    config: &'config crate::config::SniffTestConfig,
) -> Vec<Box<dyn Effect + 'config>> {
    [
        effect::<panic::Panic>(config.effect("panic")),
        effect::<safety::Safety>(config.effect("safety")),
    ]
    .into_iter()
    .filter(|effect| selection.selects(effect.key()))
    .collect()
}

#[cfg(test)]
#[must_use]
pub fn registered_effect_configs() -> std::collections::BTreeMap<String, EffectConfig> {
    [
        ("panic", panic::Panic::default_config()),
        ("safety", safety::Safety::default_config()),
    ]
    .into_iter()
    .map(|(name, config)| (name.to_owned(), config))
    .collect()
}

#[cfg(test)]
#[must_use]
pub fn selected_effects(selection: &EffectSelection) -> Vec<EffectMetadata> {
    selected_effect_objects(selection, &crate::config::test_config())
        .into_iter()
        .map(|effect| effect.metadata().clone())
        .collect()
}

/// Built-in effect definition. Compiler passes only discover concrete seeds;
/// obligation and justification semantics are supplied by shared tracking.
pub trait EffectSpec: 'static {
    const EFFECT_NAME: &'static str;
    const OBLIGATION: &'static str;
    const JUSTIFICATION: &'static str;
    const USES_ENCLOSING_SCOPE_MARKER: bool = false;

    fn default_config() -> EffectConfig;
    fn register_passes(registry: &mut EffectPassRegistry);
}

/// Object-safe effect definition with its invocation's read-only configuration.
///
/// Framework code uses this interface after registration so adding an effect
/// does not require another type-directed branch in extraction or reporting.
pub trait Effect: Send + Sync {
    fn metadata(&self) -> &EffectMetadata;
    fn config(&self) -> &EffectConfig;

    fn register_passes(&self, registry: &mut EffectPassRegistry);

    fn key(&self) -> &EffectKey {
        &self.metadata().key
    }
}

struct EffectAdapter<'config, E: EffectSpec> {
    metadata: EffectMetadata,
    config: &'config EffectConfig,
    marker: PhantomData<fn() -> E>,
}

impl<'config, E: EffectSpec> EffectAdapter<'config, E> {
    fn new(config: &'config EffectConfig) -> Self {
        Self {
            metadata: EffectMetadata::of::<E>(),
            config,
            marker: PhantomData,
        }
    }
}

impl<E: EffectSpec> Effect for EffectAdapter<'_, E> {
    fn metadata(&self) -> &EffectMetadata {
        &self.metadata
    }

    fn config(&self) -> &EffectConfig {
        self.config
    }

    fn register_passes(&self, registry: &mut EffectPassRegistry) {
        E::register_passes(registry);
    }
}

#[must_use]
pub fn effect<E: EffectSpec>(config: &EffectConfig) -> Box<dyn Effect + '_> {
    Box::new(EffectAdapter::<E>::new(config))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectMetadata {
    pub key: EffectKey,
    pub obligation: &'static str,
    pub justification: &'static str,
    pub uses_enclosing_scope_marker: bool,
}

impl EffectMetadata {
    #[must_use]
    pub fn of<E: EffectSpec>() -> Self {
        assert!(!E::EFFECT_NAME.is_empty(), "effect name must not be empty");
        assert!(
            !E::OBLIGATION.is_empty(),
            "obligation heading must not be empty"
        );
        assert!(
            !E::JUSTIFICATION.is_empty(),
            "justification marker must not be empty"
        );
        Self {
            key: EffectKey::new(E::EFFECT_NAME),
            obligation: E::OBLIGATION,
            justification: E::JUSTIFICATION,
            uses_enclosing_scope_marker: E::USES_ENCLOSING_SCOPE_MARKER,
        }
    }
}

#[must_use]
#[cfg(test)]
pub fn annotation_kind<E: EffectSpec>(role: AnnotationRole) -> AnnotationFactKind {
    AnnotationFactKind::new(EffectKey::new(E::EFFECT_NAME), role)
}

/// Effects enabled for one sniff-test invocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectSelection {
    /// `None` selects every registered effect.
    #[serde(default)]
    only: Option<BTreeSet<EffectKey>>,
}

impl EffectSelection {
    #[cfg(test)]
    #[must_use]
    pub fn registered_keys() -> Vec<EffectKey> {
        vec![EffectKey::new("panic"), EffectKey::new("safety")]
    }
    #[must_use]
    pub const fn all() -> Self {
        Self { only: None }
    }

    #[must_use]
    pub fn only(effects: impl IntoIterator<Item = EffectKey>) -> Self {
        Self {
            only: Some(effects.into_iter().collect()),
        }
    }

    #[must_use]
    pub fn from_keys(effects: Vec<EffectKey>) -> Self {
        if effects.is_empty() {
            Self::all()
        } else {
            Self::only(effects)
        }
    }

    #[must_use]
    pub fn selects(&self, effect: &EffectKey) -> bool {
        self.only
            .as_ref()
            .is_none_or(|selected| selected.contains(effect))
    }

    #[must_use]
    pub fn fingerprint(&self, registered_keys: &[EffectKey]) -> String {
        const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
        const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

        let mut selected = registered_keys
            .iter()
            .filter(|key| self.selects(key))
            .map(|key| key.as_str().to_owned())
            .collect::<Vec<_>>();
        selected.sort_unstable();
        let hash = selected.iter().fold(FNV_OFFSET_BASIS, |mut hash, effect| {
            for byte in effect.len().to_le_bytes().iter().chain(effect.as_bytes()) {
                hash = (hash ^ u64::from(*byte)).wrapping_mul(FNV_PRIME);
            }
            hash
        });
        format!("{hash:016x}")
    }
}

impl Default for EffectSelection {
    fn default() -> Self {
        Self::all()
    }
}

/// One raw call branch that actually produced an invocation-level effect.
///
/// Several rustc edges can share one source [`effect_tracing::InvocationId`].
/// The engine keeps that source identity grouped, while reporting uses these
/// branches to avoid borrowing an unrelated target, span, or contract.
#[derive(Clone, Debug)]
pub struct InvocationSourceBranch {
    edge: CallFact,
    target: Option<FunctionTargetFact>,
}

impl InvocationSourceBranch {
    pub(super) fn new(edge: CallFact, target: Option<FunctionTargetFact>) -> Self {
        Self { edge, target }
    }

    #[must_use]
    pub const fn edge(&self) -> &CallFact {
        &self.edge
    }

    #[must_use]
    pub const fn target(&self) -> Option<&FunctionTargetFact> {
        self.target.as_ref()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeError {
    message: String,
}

impl ProbeError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ProbeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ProbeError {}

#[cfg(test)]
mod tests;
