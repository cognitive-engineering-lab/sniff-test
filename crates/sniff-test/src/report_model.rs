//! Policy-neutral finding values shared by effect tracing and report adapters.

use crate::artifact::{
    CallId, CallKindFact, CompilerAssertKind, ContractRequirementFact, FunctionId,
    MarkerEvidenceState, SafetyOpKind, SourceRangeFact,
};
use crate::report_roots::ReportRootKind;
use serde::Serialize;

/// Selected workspace report root and stable reporting metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InterpretationRoot {
    pub(crate) function: FunctionId,
    pub(crate) path: String,
    pub(crate) kind: ReportRootKind,
}

/// Effect traces projected onto one selected reporting root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RootInterpretation {
    pub(crate) root: InterpretationRoot,
    pub(crate) findings: Vec<InterpretedFinding>,
    pub(crate) completeness: EffectCompleteness,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EffectCompleteness {
    pub(crate) panic: DomainCompleteness,
    pub(crate) safety: DomainCompleteness,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DomainCompleteness {
    pub(crate) complete: bool,
    pub(crate) reasons: Vec<IncompleteReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum IncompleteTraceKind {
    PanicEffect,
    SafetyEffect,
    PanicComment,
    SafetyComment,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TraceFrontier {
    pub(crate) function: FunctionId,
    pub(crate) path: String,
    pub(crate) source_range: Option<SourceRangeFact>,
    pub(crate) trace: InterpretedTrace,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IncompleteReason {
    TraceDepth {
        max_depth: usize,
        trace_kind: IncompleteTraceKind,
        frontier: TraceFrontier,
    },
    TraceStateBudget {
        budget: usize,
        trace_kind: IncompleteTraceKind,
        frontier: TraceFrontier,
    },
    MissingBody {
        function: FunctionId,
        path: String,
        source_range: Option<SourceRangeFact>,
        trace: InterpretedTrace,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InterpretedFinding {
    pub(crate) kind: InterpretedFindingKind,
    pub(crate) function: FunctionId,
    pub(crate) function_path: String,
    pub(crate) target: Option<InterpretedTarget>,
    pub(crate) source_range: Option<SourceRangeFact>,
    pub(crate) marker_evidence: Option<MarkerEvidenceState>,
    pub(crate) trace: InterpretedTrace,
    pub(crate) missing_requirements: Vec<ContractRequirementFact>,
    pub(crate) requirements: Vec<ContractRequirementFact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InterpretedTarget {
    pub(crate) function: Option<FunctionId>,
    pub(crate) path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InterpretedTrace {
    pub(crate) steps: Vec<InterpretedTraceStep>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InterpretedTraceStep {
    pub(crate) caller: FunctionId,
    pub(crate) caller_path: String,
    pub(crate) call: CallId,
    /// The real source invocation whose marker may contain this trace.
    /// Synthetic macro, transparent-body, assert, and unsafe-operation steps
    /// deliberately leave this absent.
    pub(crate) marker_call: Option<CallId>,
    pub(crate) kind: InterpretedTraceStepKind,
    pub(crate) source_range: Option<SourceRangeFact>,
    pub(crate) target: Option<FunctionId>,
    pub(crate) target_path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum InterpretedTraceStepKind {
    Reachability(CallKindFact),
    UnsafeOperation(SafetyOpKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum InterpretedSafetyCallKind {
    Unsafe,
    Obligation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum UnresolvedCallCoverage {
    None,
    Partial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum UnresolvedCallMechanism {
    FunctionPointer,
    DynamicDispatch,
    GenericDispatch,
    Opaque,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct UnresolvedCallSite {
    pub(crate) coverage: UnresolvedCallCoverage,
    pub(crate) mechanism: UnresolvedCallMechanism,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InterpretedFindingKind {
    CompilerAssert { kind: CompilerAssertKind },
    PanicSink,
    DocumentedPanic,
    UnresolvedPanicCallTarget { site: UnresolvedCallSite },
    MissingSafetyDocs,
    SafetyCall { kind: InterpretedSafetyCallKind },
    UnresolvedSafetyCallTarget { site: UnresolvedCallSite },
    UnsafeOperation { kind: SafetyOpKind },
    AmbiguousPanicRequirement { normalized_name: String },
    AmbiguousSafetyRequirement { normalized_name: String },
    AmbiguousPanicMarker { effect_count: usize },
    AmbiguousSafetyMarker { effect_count: usize },
}
