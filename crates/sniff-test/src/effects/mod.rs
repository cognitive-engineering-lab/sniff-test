pub(crate) mod concrete;
pub(crate) mod obligation;
pub(crate) mod panic;
pub(crate) mod safety;
pub(crate) mod trust;

use std::fmt;

use crate::annotations::AnnotationDomain;
use crate::artifact::{CallFact, DefinitionNamespaceIndex, EffectFact, FunctionTargetFact};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use crate::compiler::effect_passes::EffectPassRegistry;
use crate::path_patterns::PathPatterns;

use self::concrete::{InvocationSourceMatch, OwnerProjection};

/// Built-in effect definition. Compiler passes only discover concrete seeds;
/// obligation and justification semantics are supplied by shared tracking.
pub(crate) trait Effect {
    type Config: EffectConfig;

    const EFFECT_NAME: &'static str;
    const DOMAIN: AnnotationDomain;
    const OBLIGATION: &'static str;
    const JUSTIFICATION: &'static str;

    fn register_passes(registry: &mut EffectPassRegistry);

    /// Classifies an extracted operation as a source for this effect and
    /// selects how its artifact owner maps onto invocation-graph functions.
    fn operation_source(effect: &EffectFact) -> Option<OwnerProjection>;

    /// Classifies one extracted call as an invocation-level source.
    fn invocation_source(
        config: &Self::Config,
        call: &CallFact,
        namespaces: &DefinitionNamespaceIndex,
    ) -> Option<InvocationSourceMatch>;
}

/// Common, read-only configuration exposed to framework-owned seed probing.
///
/// Concrete probe policy is derived from this view; it is not embedded in an
/// effect's user-facing configuration.
pub(crate) trait EffectConfig {
    fn ignored_namespaces(&self) -> &PathPatterns;
    fn trusted_boundary_namespaces(&self) -> &PathPatterns;

    /// Namespace-classified concrete sources which compete with trusted
    /// boundaries. A more precise source match wins, preserving the existing
    /// panic-sink/trusted-boundary precedence rule.
    fn source_boundary_namespaces(&self) -> Option<&PathPatterns> {
        None
    }
}

/// Effect domains enabled for one sniff-test invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EffectSelection {
    panic: bool,
    safety: bool,
}

impl EffectSelection {
    #[must_use]
    pub(crate) fn from_effects(effects: &[EffectDomain]) -> Self {
        if effects.is_empty() {
            return Self::default();
        }
        Self {
            panic: effects.contains(&EffectDomain::Panic),
            safety: effects.contains(&EffectDomain::Safety),
        }
    }

    #[must_use]
    pub(crate) const fn tracks_panic(self) -> bool {
        self.panic
    }

    #[must_use]
    pub(crate) const fn tracks_safety(self) -> bool {
        self.safety
    }

    #[must_use]
    pub(crate) const fn fingerprint(self) -> &'static str {
        match (self.panic, self.safety) {
            (true, true) => "all",
            (true, false) => "panic",
            (false, true) => "safety",
            (false, false) => "none",
        }
    }
}

impl Default for EffectSelection {
    fn default() -> Self {
        Self {
            panic: true,
            safety: true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum EffectDomain {
    Panic,
    Safety,
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
