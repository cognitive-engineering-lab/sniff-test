//! Validated, exact-generation program indexes for workspace traversal.
//!
//! This boundary validates shared program, provenance, unsafe-operation, and
//! marker topology. Pack-local contract fact metadata remains owned by each
//! domain's existing workspace preflight; this index deliberately does not
//! duplicate panic/safety requirement policy or normalization.

mod composition;
mod index;
mod topology;

#[allow(
    unused_imports,
    reason = "root traversal consumes these composition schemas at the authority cutover"
)]
pub(crate) use composition::{
    CallableBodySelectionKind, CallableInvocationTargetsCallable, CallableResolutionKind,
    CallableSelectsFunctionBody, ConsumerOccurrenceReconcilesWith,
    ConsumerOccurrenceReconciliationKind, ConsumerOverlayUsesDefiningSourceBody,
};
#[allow(
    unused_imports,
    reason = "the public typed query surface is consumed at the traversal cutover"
)]
pub(crate) use index::{
    FunctionBodyCandidate, ScopedProgramEntity, VerifiedArtifactOwner, WorkspaceProgramIndex,
    WorkspaceProgramIndexError, WorkspaceProgramQuery,
};
#[allow(
    unused_imports,
    reason = "typed traversal consumes indexed topology candidates at the authority cutover"
)]
pub(crate) use topology::{
    CallableEvidenceCandidate, IndexedCallMacroCallsite, IndexedCallMacroPath,
    IndexedCallOccurrence, IndexedCallSite, IndexedCallSourceAnchor, IndexedCallTarget,
    IndexedCallableEvidence, IndexedContract, IndexedEffectMacroCallsite, IndexedEffectMacroPath,
    IndexedEffectSite, IndexedEffectSourceAnchor, IndexedMarkerCandidate, IndexedUnsafeOperation,
    IndexedUnsafeOperationMacroCallsite, IndexedUnsafeOperationMacroPath,
    IndexedUnsafeOperationSafetyGroup, IndexedUnsafeOperationSourceAnchor, ScopedRequirement,
};

use super::super::pack::{AnalysisRegistry, PackRegistrationError};

pub(super) fn register_composition<C: ?Sized>(
    registry: &mut AnalysisRegistry<C>,
) -> Result<(), PackRegistrationError> {
    composition::register(registry)
}

#[cfg(test)]
mod tests;
