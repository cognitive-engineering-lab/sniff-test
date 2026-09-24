pub(crate) mod concrete;
pub(crate) mod obligation;
pub(crate) mod panic;
pub(crate) mod safety;
pub(crate) mod trust;
pub(crate) mod visit;

use std::collections::BTreeSet;
use std::fmt;
use std::marker::PhantomData;

#[cfg(test)]
use crate::artifact::{AnnotationFactKind, AnnotationRole};
use crate::artifact::{CallFact, EffectKey, FunctionTargetFact};
use serde::{Deserialize, Serialize};

use crate::config::{EffectFindingLints, EffectiveCoverageConfig, LintLevel, SniffTestConfig};
use crate::path_patterns::PathPatterns;

use self::visit::EffectPassRegistry;

/// Built-in effect definition. Compiler passes only discover concrete seeds;
/// obligation and justification semantics are supplied by shared tracking.
pub(crate) trait EffectSpec: 'static {
    type Config: EffectConfig;

    const EFFECT_NAME: &'static str;
    const OBLIGATION: &'static str;
    const JUSTIFICATION: &'static str;
    const USES_ENCLOSING_SCOPE_MARKER: bool = false;

    fn register_passes(registry: &mut EffectPassRegistry);
}

/// Object-safe effect definition with its invocation's read-only configuration.
///
/// Framework code uses this interface after registration so adding an effect
/// does not require another type-directed branch in extraction or reporting.
pub(crate) trait Effect: Send + Sync {
    fn metadata(&self) -> &EffectMetadata;
    fn config(&self) -> &dyn EffectConfig;

    fn register_passes(&self, registry: &mut EffectPassRegistry);

    fn key(&self) -> &EffectKey {
        &self.metadata().key
    }
}

struct EffectAdapter<'config, E: EffectSpec> {
    metadata: EffectMetadata,
    config: &'config E::Config,
    marker: PhantomData<fn() -> E>,
}

impl<'config, E: EffectSpec> EffectAdapter<'config, E> {
    fn new(config: &'config E::Config) -> Self {
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

    fn config(&self) -> &dyn EffectConfig {
        self.config
    }

    fn register_passes(&self, registry: &mut EffectPassRegistry) {
        E::register_passes(registry);
    }
}

#[must_use]
pub(crate) fn effect<E: EffectSpec>(config: &E::Config) -> Box<dyn Effect + '_> {
    Box::new(EffectAdapter::<E>::new(config))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EffectMetadata {
    pub(crate) key: EffectKey,
    pub(crate) obligation: &'static str,
    pub(crate) justification: &'static str,
    pub(crate) uses_enclosing_scope_marker: bool,
}

impl EffectMetadata {
    #[must_use]
    pub(crate) fn of<E: EffectSpec>() -> Self {
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
pub(crate) fn registered_effects(config: &SniffTestConfig) -> Vec<Box<dyn Effect + '_>> {
    let effects = vec![
        effect::<panic::Panic>(&config.panics),
        effect::<safety::Safety>(&config.safety),
    ];
    let unique = effects
        .iter()
        .map(|effect| effect.key())
        .collect::<BTreeSet<_>>();
    assert_eq!(unique.len(), effects.len(), "effect names must be unique");
    effects
}

#[must_use]
#[cfg(test)]
pub(crate) fn selected_effects(selection: &EffectSelection) -> Vec<EffectMetadata> {
    selected_effect_objects(selection, &SniffTestConfig::default())
        .into_iter()
        .map(|effect| effect.metadata().clone())
        .collect()
}

#[must_use]
pub(crate) fn selected_effect_objects<'config>(
    selection: &EffectSelection,
    config: &'config SniffTestConfig,
) -> Vec<Box<dyn Effect + 'config>> {
    registered_effects(config)
        .into_iter()
        .filter(|effect| selection.selects(effect.key()))
        .collect()
}

#[must_use]
#[cfg(test)]
pub(crate) fn annotation_kind<E: EffectSpec>(role: AnnotationRole) -> AnnotationFactKind {
    AnnotationFactKind::new(EffectKey::new(E::EFFECT_NAME), role)
}

/// Common, read-only policy exposed to probing and reporting.
pub(crate) trait EffectConfig: Sync {
    fn ignored_namespaces(&self) -> &PathPatterns;
    fn trusted_boundary_namespaces(&self) -> &PathPatterns;
    fn finding_lints(&self) -> EffectFindingLints;
    fn operation_lint(&self, operation: Option<&str>) -> LintLevel;
    fn effective_coverage(&self) -> EffectiveCoverageConfig;
}

/// Effects enabled for one sniff-test invocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EffectSelection {
    /// `None` selects every registered effect.
    #[serde(default)]
    only: Option<BTreeSet<EffectKey>>,
}

impl EffectSelection {
    #[must_use]
    pub(crate) const fn all() -> Self {
        Self { only: None }
    }

    #[must_use]
    pub(crate) fn only(effects: impl IntoIterator<Item = EffectKey>) -> Self {
        Self {
            only: Some(effects.into_iter().collect()),
        }
    }

    #[must_use]
    pub(crate) fn from_keys(effects: Vec<EffectKey>) -> Self {
        if effects.is_empty() {
            Self::all()
        } else {
            Self::only(effects)
        }
    }

    #[must_use]
    pub(crate) fn selects(&self, effect: &EffectKey) -> bool {
        self.only
            .as_ref()
            .is_none_or(|selected| selected.contains(effect))
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) fn tracks_panic(&self) -> bool {
        self.selects(&EffectKey::new(panic::Panic::EFFECT_NAME))
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) fn tracks_safety(&self) -> bool {
        self.selects(&EffectKey::new(safety::Safety::EFFECT_NAME))
    }

    #[must_use]
    pub(crate) fn fingerprint(&self) -> String {
        const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
        const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

        let config = SniffTestConfig::default();
        let mut selected = registered_effects(&config)
            .into_iter()
            .filter(|effect| self.selects(effect.key()))
            .map(|effect| effect.key().as_str().to_owned())
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

    #[must_use]
    pub(crate) fn registered_keys() -> Vec<EffectKey> {
        let config = SniffTestConfig::default();
        registered_effects(&config)
            .into_iter()
            .map(|effect| effect.key().clone())
            .collect()
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
pub(crate) struct InvocationSourceBranch {
    edge: CallFact,
    target: Option<FunctionTargetFact>,
}

impl InvocationSourceBranch {
    pub(super) fn new(edge: CallFact, target: Option<FunctionTargetFact>) -> Self {
        Self { edge, target }
    }

    #[must_use]
    pub(crate) const fn edge(&self) -> &CallFact {
        &self.edge
    }

    #[must_use]
    pub(crate) const fn target(&self) -> Option<&FunctionTargetFact> {
        self.target.as_ref()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProbeError {
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
