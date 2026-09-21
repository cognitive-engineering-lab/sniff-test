pub(crate) mod concrete;
pub(crate) mod obligation;
pub(crate) mod panic;
pub(crate) mod safety;
pub(crate) mod trust;
pub(crate) mod visit;

use std::fmt;

use crate::artifact::{
    AnnotationFactKind, AnnotationRole, CallFact, EffectKey, FunctionTargetFact,
};
use clap::ValueEnum;
use rustc_hir::def_id::DefId;
use rustc_middle::ty::TyCtxt;
use serde::{Deserialize, Serialize};

use crate::path_patterns::PathPatterns;

use self::visit::EffectPassRegistry;

/// Built-in effect definition. Compiler passes only discover concrete seeds;
/// obligation and justification semantics are supplied by shared tracking.
pub(crate) trait Effect {
    type Config: EffectConfig;

    const EFFECT_NAME: &'static str;
    const OBLIGATION: &'static str;
    const JUSTIFICATION: &'static str;
    const USES_ENCLOSING_SCOPE_MARKER: bool = false;

    fn register_passes(registry: &mut EffectPassRegistry);
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
    pub(crate) fn of<E: Effect>() -> Self {
        Self {
            key: EffectKey::new(E::EFFECT_NAME),
            obligation: E::OBLIGATION,
            justification: E::JUSTIFICATION,
            uses_enclosing_scope_marker: E::USES_ENCLOSING_SCOPE_MARKER,
        }
    }
}

#[must_use]
pub(crate) fn selected_effects(selection: EffectSelection) -> Vec<EffectMetadata> {
    let mut effects = Vec::new();
    if selection.tracks_panic() {
        effects.push(EffectMetadata::of::<panic::Panic>());
    }
    if selection.tracks_safety() {
        effects.push(EffectMetadata::of::<safety::Safety>());
    }
    effects
}

#[must_use]
pub(crate) fn annotation_kind<E: Effect>(role: AnnotationRole) -> AnnotationFactKind {
    AnnotationFactKind::new(EffectKey::new(E::EFFECT_NAME), role)
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

    /// Registers every selected effect through the common effect interface.
    ///
    /// Compiler extraction deliberately does not know the built-in effect
    /// types. This is the compatibility bridge for the current fixed
    /// selection representation; a plugin registry can replace the body
    /// without changing extraction.
    pub(crate) fn register_passes(self, registry: &mut EffectPassRegistry) {
        if self.tracks_panic() {
            registry.register_effect::<panic::Panic>();
        }
        if self.tracks_safety() {
            registry.register_effect::<safety::Safety>();
        }
    }

    /// Whether this selected set needs Rust unsafe-signature facts. Kept on
    /// the selection boundary so compiler extraction does not name the effect
    /// which owns that interpretation.
    #[must_use]
    pub(crate) fn function_requires_explicit_context(self, tcx: TyCtxt<'_>, def_id: DefId) -> bool {
        self.tracks_safety() && safety::visit::fn_def_is_unsafe(tcx, def_id)
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
