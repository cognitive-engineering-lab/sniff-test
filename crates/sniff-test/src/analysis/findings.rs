//! Policy-neutral finding values shared by typed evaluation and report adapters.

use super::ir::{CallEdgeKindIr, CallId, ContractRequirementIr, FunctionId, SourceRangeIr};
use crate::report_roots::ReportRootKind;
use crate::safety::SafetyOpKind;

/// Selected workspace report root and stable reporting metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InterpretationRoot {
    pub(crate) function: FunctionId,
    pub(crate) path: String,
    pub(crate) kind: ReportRootKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IncompleteReason {
    NodeLimit {
        limit: usize,
    },
    MissingBody {
        function: FunctionId,
        path: String,
        source_range: Option<SourceRangeIr>,
        trace: InterpretedTrace,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InterpretedFinding {
    pub(crate) kind: InterpretedFindingKind,
    pub(crate) function: FunctionId,
    pub(crate) function_path: String,
    pub(crate) target: Option<InterpretedTarget>,
    pub(crate) source_range: Option<SourceRangeIr>,
    pub(crate) trace: InterpretedTrace,
    pub(crate) missing_requirements: Vec<ContractRequirementIr>,
    pub(crate) requirements: Vec<ContractRequirementIr>,
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
    pub(crate) kind: InterpretedTraceStepKind,
    pub(crate) source_range: Option<SourceRangeIr>,
    pub(crate) target: Option<FunctionId>,
    pub(crate) target_path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum InterpretedTraceStepKind {
    Reachability(CallEdgeKindIr),
    UnsafeOperation(SafetyOpKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum InterpretedSafetyCallKind {
    Unsafe,
    Obligation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InterpretedFindingKind {
    PanicSink,
    DocumentedPanic {
        trusted: bool,
    },
    OpaquePanicBoundary {
        description: String,
    },
    MissingSafetyDocs,
    SafetyCall {
        kind: InterpretedSafetyCallKind,
        trusted: bool,
    },
    OpaqueSafetyBoundary {
        description: String,
    },
    UnsafeOperation {
        kind: SafetyOpKind,
    },
    AmbiguousPanicRequirement {
        normalized_name: String,
    },
    AmbiguousSafetyRequirement {
        normalized_name: String,
    },
    AmbiguousPanicMarker {
        effect_count: usize,
    },
    AmbiguousSafetyMarker {
        effect_count: usize,
    },
}
