//! Typed facts and root-specific evaluation rules for unified panic authority.

pub(crate) mod assertion_collector;
pub(crate) mod assertion_index;
mod call_ingress;
mod call_issues;
mod call_matching;
pub(crate) mod call_model;
mod call_trace;
mod compiler_assert_ingress;
mod compiler_assert_inputs;
mod compiler_assert_trace;
mod completeness;
pub(crate) mod contract_collector;
mod contract_index;
pub(crate) mod contracts;
pub(crate) mod model;
mod render;
mod root_contract;
pub(crate) mod rules;
mod trace_route;

pub(crate) use call_ingress::PanicCallInputPack;
pub(crate) use call_issues::{
    expected_duplicate_panic_call_requirement_issues, expected_unsatisfied_panic_call_issues,
};
pub(crate) use call_matching::expected_matches_from_obligations;
pub(crate) use call_model::{
    DuplicatePanicCallRequirementIssue, PanicCallBoundaryKind, PanicCallEvidenceMatch,
    PanicCallObligation, PanicCallOpaqueKind, PanicCallRequirementMatchId,
    PanicCallRequirementValue, UnsatisfiedPanicCallIssue,
};
pub(crate) use call_model::{
    PanicCallResolution, PanicCallTargetAuthority, PanicCallableResolutionKind,
};
pub(crate) use call_trace::{
    PanicCallSemanticEdge, PanicCallSemanticTrace, PanicCallSemanticTraceStepKind,
    PanicCallTraceError, PanicCallTraceNode, PanicCallTraceProjector,
};
pub(crate) use compiler_assert_ingress::CompilerAssertInputPack;
pub(crate) use compiler_assert_inputs::PanicRootInputs;
pub(crate) use compiler_assert_inputs::{
    CompilerAssertInputError, CompilerAssertRootInputs, CompilerAssertRootRequest,
    PreparedCompilerAssertRootBatch,
};
pub(crate) use compiler_assert_inputs::{PanicCallInputKind, PanicOpaqueBoundaryKind};
pub(crate) use compiler_assert_trace::{
    CompilerAssertSemanticEdge, CompilerAssertSemanticNodeRole, CompilerAssertSemanticTrace,
    CompilerAssertSemanticTraceStep, CompilerAssertTraceError, CompilerAssertTraceProjector,
};
#[cfg(test)]
pub(crate) use completeness::PanicCompletenessSemanticStep;
pub(crate) use completeness::{
    PanicAnalysisIncompleteIssue, PanicCompletenessOutcome, PanicCompletenessPack,
    PanicCompletenessReason, PanicIncompleteReason,
};
#[cfg(test)]
pub(crate) use contract_index::EffectivePanicContractOrigin;
pub(crate) use render::{CompilerAssertPresentation, coarse_public_assert_kind};
pub(crate) use root_contract::{DuplicatePanicRootRequirementIssue, PanicRootContractPack};
pub(crate) use root_contract::{root_contract, root_contract_boundary};

/// Returns the pack-owned public presentation of one precise MIR assertion.
#[must_use]
pub(crate) fn compiler_assert_presentation(
    kind: model::MirAssertKind,
) -> CompilerAssertPresentation {
    render::compiler_assert_presentation(kind)
}

#[cfg(test)]
mod tests;
