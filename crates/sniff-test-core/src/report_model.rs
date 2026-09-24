//! Policy-neutral finding values shared by effect tracing and report adapters.

use crate::artifact::{
    CallId, CallKindFact, ContractRequirementFact, EffectKey, EffectKind, FunctionId,
    MarkerEvidenceState, SourceRangeFact,
};
use crate::effects::EffectMetadata;
use crate::report_roots::ReportRootKind;
use serde::Serialize;
use std::collections::BTreeMap;

/// Selected workspace report root and stable reporting metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterpretationRoot {
    pub function: FunctionId,
    pub path: String,
    pub kind: ReportRootKind,
}

/// Effect traces projected onto one selected reporting root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootInterpretation {
    pub root: InterpretationRoot,
    pub findings: Vec<InterpretedFinding>,
    pub completeness: EffectCompleteness,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectCompleteness {
    pub effects: BTreeMap<EffectKey, DomainCompleteness>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainCompleteness {
    pub complete: bool,
    pub reasons: Vec<IncompleteReason>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceFrontier {
    pub function: FunctionId,
    pub path: String,
    pub source_range: Option<SourceRangeFact>,
    pub trace: InterpretedTrace,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncompleteReason {
    TraceDepth {
        max_depth: usize,
        frontier: TraceFrontier,
    },
    TraceStateBudget {
        budget: usize,
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
pub struct InterpretedFinding {
    pub effect: EffectMetadata,
    pub kind: InterpretedFindingKind,
    pub function: FunctionId,
    pub function_path: String,
    pub callee: Option<InterpretedCallee>,
    pub source_range: Option<SourceRangeFact>,
    pub contract_source_range: Option<SourceRangeFact>,
    pub marker_evidence: Option<MarkerEvidenceState>,
    pub trace: InterpretedTrace,
    pub missing_requirements: Vec<ContractRequirementFact>,
    pub requirements: Vec<ContractRequirementFact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterpretedCallee {
    pub function: Option<FunctionId>,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterpretedTrace {
    pub steps: Vec<InterpretedTraceStep>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterpretedTraceStep {
    pub caller: FunctionId,
    pub caller_path: String,
    pub call: CallId,
    /// The real source invocation whose marker may contain this trace.
    /// Synthetic macro, transparent-body, assert, and unsafe-operation steps
    /// deliberately leave this absent.
    pub marker_call: Option<CallId>,
    pub kind: InterpretedTraceStepKind,
    pub source_range: Option<SourceRangeFact>,
    pub target: Option<FunctionId>,
    pub target_path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InterpretedTraceStepKind {
    Reachability(CallKindFact),
    EffectOperation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnresolvedCallCoverage {
    None,
    Partial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnresolvedCallMechanism {
    FunctionPointer,
    DynamicDispatch,
    GenericDispatch,
    Opaque,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct UnresolvedCallSite {
    pub coverage: UnresolvedCallCoverage,
    pub mechanism: UnresolvedCallMechanism,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EffectFindingClass {
    ConcreteOperation,
    ConcreteInvocation,
    UndocumentedInvocation,
    DocumentedObligation,
    UnresolvedCallTarget,
    AmbiguousMarker,
    AmbiguousRequirement,
    AnalysisIncomplete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterpretedFindingKind {
    Operation { operation: EffectKind },
    Invocation { operation: EffectKind },
    UndocumentedInvocation { operation: EffectKind },
    DocumentedObligation,
    UnresolvedCallTarget { site: UnresolvedCallSite },
    AmbiguousRequirement { normalized_name: String },
    AmbiguousMarker { effect_count: usize },
}

impl InterpretedFindingKind {
    #[must_use]
    pub const fn class(&self) -> EffectFindingClass {
        match self {
            Self::Operation { .. } => EffectFindingClass::ConcreteOperation,
            Self::Invocation { .. } => EffectFindingClass::ConcreteInvocation,
            Self::UndocumentedInvocation { .. } => EffectFindingClass::UndocumentedInvocation,
            Self::DocumentedObligation => EffectFindingClass::DocumentedObligation,
            Self::UnresolvedCallTarget { .. } => EffectFindingClass::UnresolvedCallTarget,
            Self::AmbiguousRequirement { .. } => EffectFindingClass::AmbiguousRequirement,
            Self::AmbiguousMarker { .. } => EffectFindingClass::AmbiguousMarker,
        }
    }
}
