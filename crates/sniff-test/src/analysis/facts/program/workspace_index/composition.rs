//! Root-specific program-resolution relation schemas.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

use super::super::super::pack::{AnalysisRegistry, PackRegistrationError};
use super::super::super::schema::{CompositionRelationSchema, RelationSchema, RowSchema};
use super::super::FunctionEntity;
use super::super::topology::{CallOccurrenceEntity, CallableEntity, CallableKey};

/// Why a callable selected one function body for this evaluation root.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CallableBodySelectionKind {
    ExactPreferred,
    GenericPreferred,
    ExactDefining,
    GenericDefining,
}

/// Selects one exact-generation body without making key equality an edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct CallableSelectsFunctionBody {
    selection_kind: CallableBodySelectionKind,
}

impl RowSchema for CallableSelectsFunctionBody {
    const ID: &'static str = "sniff-test.core.composition.callable-selects-function-body";
    const VERSION: u32 = 1;
}

impl RelationSchema for CallableSelectsFunctionBody {
    type From = CallableEntity;
    type To = FunctionEntity;
}

impl CompositionRelationSchema for CallableSelectsFunctionBody {}

impl CallableSelectsFunctionBody {
    #[must_use]
    pub(crate) const fn new(selection_kind: CallableBodySelectionKind) -> Self {
        Self { selection_kind }
    }

    #[must_use]
    pub(crate) const fn selection_kind(self) -> CallableBodySelectionKind {
        self.selection_kind
    }
}

/// Semantic provenance of one erased-callable resolution.
///
/// This deliberately does not mirror rustc edge kinds. The redundant variant
/// is retained beside [`CallableKey`] for trace presentation and integrity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CallableResolutionKind {
    FunctionPointerEvidence,
    DynamicDispatchEvidence,
}

/// Connects a reachable invocation to callable metadata selected by evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct CallableInvocationTargetsCallable {
    callable_key: CallableKey,
    resolution_kind: CallableResolutionKind,
}

impl RowSchema for CallableInvocationTargetsCallable {
    const ID: &'static str = "sniff-test.core.composition.callable-invocation-targets-callable";
    const VERSION: u32 = 1;
}

impl RelationSchema for CallableInvocationTargetsCallable {
    type From = CallOccurrenceEntity;
    type To = CallableEntity;
}

impl CompositionRelationSchema for CallableInvocationTargetsCallable {}

impl CallableInvocationTargetsCallable {
    pub(crate) fn try_new(
        callable_key: CallableKey,
        resolution_kind: CallableResolutionKind,
    ) -> Result<Self, CallableResolutionError> {
        validate_resolution_kind(callable_key, resolution_kind)?;
        Ok(Self {
            callable_key,
            resolution_kind,
        })
    }

    #[must_use]
    pub(crate) const fn callable_key(&self) -> CallableKey {
        self.callable_key
    }

    #[must_use]
    pub(crate) const fn resolution_kind(&self) -> CallableResolutionKind {
        self.resolution_kind
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct EncodedCallableInvocationTargetsCallable {
    callable_key: CallableKey,
    resolution_kind: CallableResolutionKind,
}

impl<'de> Deserialize<'de> for CallableInvocationTargetsCallable {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = EncodedCallableInvocationTargetsCallable::deserialize(deserializer)?;
        Self::try_new(encoded.callable_key, encoded.resolution_kind).map_err(D::Error::custom)
    }
}

/// A callable key and semantic resolution provenance disagree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CallableResolutionError {
    callable_key: CallableKey,
    resolution_kind: CallableResolutionKind,
}

impl Display for CallableResolutionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "callable key {:?} is incompatible with {:?}",
            self.callable_key, self.resolution_kind
        )
    }
}

impl Error for CallableResolutionError {}

fn validate_resolution_kind(
    callable_key: CallableKey,
    resolution_kind: CallableResolutionKind,
) -> Result<(), CallableResolutionError> {
    if matches!(
        (callable_key, resolution_kind),
        (
            CallableKey::FnPointer(_),
            CallableResolutionKind::FunctionPointerEvidence
        ) | (
            CallableKey::DynDispatch(_),
            CallableResolutionKind::DynamicDispatchEvidence
        )
    ) {
        Ok(())
    } else {
        Err(CallableResolutionError {
            callable_key,
            resolution_kind,
        })
    }
}

/// Explicitly connects an exact consumer overlay to a defining source body.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct ConsumerOverlayUsesDefiningSourceBody {}

impl RowSchema for ConsumerOverlayUsesDefiningSourceBody {
    const ID: &'static str =
        "sniff-test.core.composition.consumer-overlay-uses-defining-source-body";
    const VERSION: u32 = 1;
}

impl RelationSchema for ConsumerOverlayUsesDefiningSourceBody {
    type From = FunctionEntity;
    type To = FunctionEntity;
}

impl CompositionRelationSchema for ConsumerOverlayUsesDefiningSourceBody {}

impl ConsumerOverlayUsesDefiningSourceBody {
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {}
    }
}

/// Why an overlay occurrence was paired with a defining-source occurrence.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ConsumerOccurrenceReconciliationKind {
    SemanticTarget,
    SourceFallback,
}

/// Explicitly reconciles one consumer occurrence with defining-source facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct ConsumerOccurrenceReconcilesWith {
    reconciliation_kind: ConsumerOccurrenceReconciliationKind,
}

impl RowSchema for ConsumerOccurrenceReconcilesWith {
    const ID: &'static str = "sniff-test.core.composition.consumer-occurrence-reconciles-with";
    const VERSION: u32 = 1;
}

impl RelationSchema for ConsumerOccurrenceReconcilesWith {
    type From = CallOccurrenceEntity;
    type To = CallOccurrenceEntity;
}

impl CompositionRelationSchema for ConsumerOccurrenceReconcilesWith {}

impl ConsumerOccurrenceReconcilesWith {
    #[must_use]
    pub(crate) const fn new(reconciliation_kind: ConsumerOccurrenceReconciliationKind) -> Self {
        Self {
            reconciliation_kind,
        }
    }

    #[must_use]
    pub(crate) const fn reconciliation_kind(self) -> ConsumerOccurrenceReconciliationKind {
        self.reconciliation_kind
    }
}

pub(super) fn register<C: ?Sized>(
    registry: &mut AnalysisRegistry<C>,
) -> Result<(), PackRegistrationError> {
    registry.register_composition_relation::<CallableSelectsFunctionBody>()?;
    registry.register_composition_relation::<CallableInvocationTargetsCallable>()?;
    registry.register_composition_relation::<ConsumerOverlayUsesDefiningSourceBody>()?;
    registry.register_composition_relation::<ConsumerOccurrenceReconcilesWith>()?;
    Ok(())
}
