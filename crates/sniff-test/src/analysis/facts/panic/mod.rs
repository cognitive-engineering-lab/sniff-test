//! Typed compiler-assert facts and root-specific panic evaluation rules.

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
pub(crate) mod contract_collector;
mod contract_index;
pub(crate) mod contracts;
pub(crate) mod model;
mod render;
pub(crate) mod rules;
mod trace_route;

#[allow(
    unused_imports,
    reason = "typed panic root preparation consumes the permanent assertion index next"
)]
pub(crate) use assertion_index::{
    IndexedMirAssert, WorkspaceMirAssertIndex, WorkspaceMirAssertIndexError,
};
#[allow(
    unused_imports,
    reason = "the additive panic-call pack is installed by the next authority-switch slice"
)]
pub(crate) use call_ingress::PanicCallInputPack;
#[allow(
    unused_imports,
    reason = "panic-call evaluation rules consume these permanent DTOs in the next slice"
)]
pub(crate) use call_model::{
    DuplicatePanicCallRequirementIssue, PanicCallBoundaryKind, PanicCallObligation,
    PanicCallOpaqueKind, PanicCallRequirementMatchId, PanicCallRequirementValue,
    UnsatisfiedPanicCallIssue,
};
#[cfg(test)]
pub(crate) use call_model::{
    PanicCallResolution, PanicCallTargetAuthority, PanicCallableResolutionKind,
};
#[cfg(test)]
pub(crate) use call_trace::{
    PanicCallSemanticEdge, PanicCallSemanticTrace, PanicCallSemanticTraceStepKind,
    PanicCallTraceError, PanicCallTraceNode, PanicCallTraceProjector,
};
pub(crate) use compiler_assert_ingress::CompilerAssertInputPack;
#[allow(
    unused_imports,
    reason = "the additive panic-call pack is installed by the next authority-switch slice"
)]
pub(crate) use compiler_assert_inputs::PanicRootInputs;
pub(crate) use compiler_assert_inputs::{
    CompilerAssertInputError, CompilerAssertRootInputs, CompilerAssertRootRequest,
    PreparedCompilerAssertRootBatch,
};
#[cfg(test)]
pub(crate) use compiler_assert_inputs::{PanicCallInputKind, PanicOpaqueBoundaryKind};
pub(crate) use compiler_assert_trace::{
    CompilerAssertSemanticEdge, CompilerAssertSemanticNodeRole, CompilerAssertSemanticTrace,
    CompilerAssertSemanticTraceStep, CompilerAssertTraceError, CompilerAssertTraceProjector,
};
#[allow(
    unused_imports,
    reason = "typed panic root preparation consumes the effective contract index next"
)]
pub(crate) use contract_index::{
    WorkspaceEffectivePanicContracts, WorkspaceEffectivePanicContractsError,
};
pub(crate) use render::{CompilerAssertPresentation, coarse_public_assert_kind};

/// Returns the pack-owned public presentation of one precise MIR assertion.
#[must_use]
pub(crate) fn compiler_assert_presentation(
    kind: model::MirAssertKind,
) -> CompilerAssertPresentation {
    render::compiler_assert_presentation(kind)
}

#[cfg(test)]
mod tests;
