//! Root-driven policy interpretation over composed policy-neutral artifact IR.

#![cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "legacy interpretation is retained only as the typed safety parity oracle"
    )
)]

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::rc::Rc;

#[cfg(test)]
use super::cache::ArtifactAnalysisCache;
#[cfg(test)]
use super::graph::ArtifactAnalysisGraph;
use super::graph::{BodyScope, LoadedFunction};
use super::ir::{
    ArtifactAnalysisIr, CallEdgeIr, CallEdgeKindIr, CallId, CallSiteId, CallTargetIr,
    CallableAttributionIr, CallableKeyIr, CompilerAssertKind, ContractRequirementIr, EffectId,
    EffectKindIr, FunctionAttributesIr, FunctionBodyIr, FunctionBodyProvenanceIr, FunctionId,
    FunctionTargetIr, MacroExpansionFrameIr, MarkerIr, MarkerKindIr, MarkerProbingIr,
    MarkerTargetIr, OpaqueTargetIr, RawContractIr, SafetyEffectGroupId, SafetyOpKind,
    SourceRangeIr,
};
use crate::config::{CallableEdgeAttribution, MarkerProbing, PanicBoundaryPolicy, SniffTestConfig};
use crate::contracts::{
    normalize_requirement_name, panic_contract_doc_summary_from_markdown,
    safety_contract_doc_summary_from_markdown,
};
use crate::report_roots::ReportRootKind;

/// Read-only function lookup used by the policy interpreter.
pub(crate) trait FunctionLookup {
    /// Resolves an exact instance, falling back to its generic definition.
    fn function(&self, function: FunctionId) -> Option<LoadedFunction<'_>>;

    /// Resolves an exact instance within one artifact, falling back only to a
    /// generic body in that same artifact.
    fn function_in_scope(
        &self,
        scope: &BodyScope,
        function: FunctionId,
    ) -> Option<LoadedFunction<'_>>;

    /// Resolves the defining artifact's facts for one function.
    ///
    /// Consumer-instantiation overlays replace calls and compiler assertions
    /// with rustc's exact monomorphized view, but only the defining artifact
    /// can extract source-level THIR unsafe-operation facts.
    fn defining_body(&self, function: FunctionId) -> Option<LoadedFunction<'_>> {
        function.resolution_candidates().find_map(|candidate| {
            self.function(candidate).filter(|body| {
                matches!(
                    body.body().provenance,
                    FunctionBodyProvenanceIr::DefiningArtifact
                )
            })
        })
    }

    /// Resolves only source-level facts from the defining artifact.
    ///
    /// Unlike [`Self::defining_body`], this may use a different exact
    /// instance with the same stable definition path. It must not be used for
    /// MIR call-graph traversal.
    fn defining_source_body(&self, function: FunctionId) -> Option<LoadedFunction<'_>> {
        self.defining_body(function)
    }

    /// Resolves a target in the current artifact context, then falls back only
    /// to facts from its defining artifact. It must never borrow an exact
    /// overlay from an unrelated consumer artifact.
    fn resolve(&self, scope: &BodyScope, function: FunctionId) -> Option<LoadedFunction<'_>> {
        self.function_in_scope(scope, function)
            .or_else(|| self.defining_body(function))
    }

    /// Whether this composed analysis is responsible for bodies from one
    /// stable crate.
    ///
    /// Implicit compiler crates such as `core` and `std` are not rustc
    /// `--extern` inputs and therefore do not have artifact-IR caches in
    /// the composed cache graph. An absent body is incomplete only when its
    /// defining artifact is managed by this lookup.
    fn manages_stable_crate_id(&self, _stable_crate_id: u64) -> bool {
        true
    }
}

impl FunctionLookup for ArtifactAnalysisIr {
    fn function(&self, function: FunctionId) -> Option<LoadedFunction<'_>> {
        self.function_body(function)
            .map(|body| LoadedFunction::new(body, BodyScope::in_memory(self)))
    }

    fn function_in_scope(
        &self,
        scope: &BodyScope,
        function: FunctionId,
    ) -> Option<LoadedFunction<'_>> {
        (scope == &BodyScope::in_memory(self))
            .then(|| self.function(function))
            .flatten()
    }

    fn defining_body(&self, function: FunctionId) -> Option<LoadedFunction<'_>> {
        self.defining_function_body(function)
            .map(|body| LoadedFunction::new(body, BodyScope::in_memory(self)))
    }

    fn defining_source_body(&self, function: FunctionId) -> Option<LoadedFunction<'_>> {
        self.defining_source_function_body(function)
            .map(|body| LoadedFunction::new(body, BodyScope::in_memory(self)))
    }
}

/// Local artifact IR together with the one crate identity it manages.
///
/// Workspace executable units do not necessarily have a rustc SVH, so their
/// IR stays in memory instead of receiving a synthetic cache identity.
pub(crate) struct InMemoryArtifactLookup<'a> {
    ir: &'a ArtifactAnalysisIr,
    stable_crate_id: u64,
}

impl<'a> InMemoryArtifactLookup<'a> {
    #[must_use]
    pub(crate) const fn new(ir: &'a ArtifactAnalysisIr, stable_crate_id: u64) -> Self {
        Self {
            ir,
            stable_crate_id,
        }
    }
}

impl FunctionLookup for InMemoryArtifactLookup<'_> {
    fn function(&self, function: FunctionId) -> Option<LoadedFunction<'_>> {
        self.ir.function(function)
    }

    fn function_in_scope(
        &self,
        scope: &BodyScope,
        function: FunctionId,
    ) -> Option<LoadedFunction<'_>> {
        self.ir.function_in_scope(scope, function)
    }

    fn defining_body(&self, function: FunctionId) -> Option<LoadedFunction<'_>> {
        self.ir.defining_body(function)
    }

    fn defining_source_body(&self, function: FunctionId) -> Option<LoadedFunction<'_>> {
        self.ir.defining_source_body(function)
    }

    fn manages_stable_crate_id(&self, stable_crate_id: u64) -> bool {
        self.stable_crate_id == stable_crate_id
    }
}

#[cfg(test)]
impl FunctionLookup for ArtifactAnalysisCache {
    fn function(&self, function: FunctionId) -> Option<LoadedFunction<'_>> {
        self.legacy_ir
            .function_body(function)
            .map(|body| LoadedFunction::new(body, BodyScope::artifact(self)))
    }

    fn function_in_scope(
        &self,
        scope: &BodyScope,
        function: FunctionId,
    ) -> Option<LoadedFunction<'_>> {
        (scope == &BodyScope::artifact(self))
            .then(|| self.function(function))
            .flatten()
    }

    fn defining_body(&self, function: FunctionId) -> Option<LoadedFunction<'_>> {
        self.legacy_ir
            .defining_function_body(function)
            .map(|body| LoadedFunction::new(body, BodyScope::artifact(self)))
    }

    fn defining_source_body(&self, function: FunctionId) -> Option<LoadedFunction<'_>> {
        self.legacy_ir
            .defining_source_function_body(function)
            .map(|body| LoadedFunction::new(body, BodyScope::artifact(self)))
    }

    fn manages_stable_crate_id(&self, stable_crate_id: u64) -> bool {
        self.artifact.id.stable_crate_id == stable_crate_id
    }
}

#[cfg(test)]
impl FunctionLookup for ArtifactAnalysisGraph {
    fn function(&self, function: FunctionId) -> Option<LoadedFunction<'_>> {
        ArtifactAnalysisGraph::function(self, function)
    }

    fn function_in_scope(
        &self,
        scope: &BodyScope,
        function: FunctionId,
    ) -> Option<LoadedFunction<'_>> {
        ArtifactAnalysisGraph::function_in_scope(self, scope, function)
    }

    fn defining_body(&self, function: FunctionId) -> Option<LoadedFunction<'_>> {
        ArtifactAnalysisGraph::defining_function(self, function)
    }

    fn defining_source_body(&self, function: FunctionId) -> Option<LoadedFunction<'_>> {
        ArtifactAnalysisGraph::defining_source_function(self, function)
    }

    fn manages_stable_crate_id(&self, stable_crate_id: u64) -> bool {
        self.artifacts()
            .any(|artifact| artifact.artifact.id.stable_crate_id == stable_crate_id)
    }
}

/// Ordered composition of local and dependency IR lookups.
pub(crate) struct LayeredFunctionLookup<'a> {
    layers: Vec<&'a dyn FunctionLookup>,
}

impl<'a> LayeredFunctionLookup<'a> {
    #[must_use]
    pub(crate) fn new(layers: Vec<&'a dyn FunctionLookup>) -> Self {
        Self { layers }
    }
}

impl FunctionLookup for LayeredFunctionLookup<'_> {
    fn function(&self, function: FunctionId) -> Option<LoadedFunction<'_>> {
        self.layers
            .iter()
            .find_map(|layer| layer.function(function))
    }

    fn function_in_scope(
        &self,
        scope: &BodyScope,
        function: FunctionId,
    ) -> Option<LoadedFunction<'_>> {
        self.layers
            .iter()
            .find_map(|layer| layer.function_in_scope(scope, function))
    }

    fn defining_body(&self, function: FunctionId) -> Option<LoadedFunction<'_>> {
        self.layers
            .iter()
            .find_map(|layer| layer.defining_body(function))
    }

    fn defining_source_body(&self, function: FunctionId) -> Option<LoadedFunction<'_>> {
        self.layers
            .iter()
            .find_map(|layer| layer.defining_source_body(function))
    }

    fn manages_stable_crate_id(&self, stable_crate_id: u64) -> bool {
        self.layers
            .iter()
            .any(|layer| layer.manages_stable_crate_id(stable_crate_id))
    }
}

/// Selected workspace report root and stable reporting metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InterpretationRoot {
    pub(crate) function: FunctionId,
    pub(crate) path: String,
    pub(crate) kind: ReportRootKind,
}

/// Findings and completeness for one selected root.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RootInterpretation {
    pub(crate) root: InterpretationRoot,
    pub(crate) findings: Vec<InterpretedFinding>,
    pub(crate) completeness: EffectCompleteness,
}

/// Safety findings and completeness for one selected root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SafetyRootInterpretation {
    pub(crate) root: InterpretationRoot,
    pub(crate) findings: Vec<InterpretedFinding>,
    pub(crate) completeness: DomainCompleteness,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EffectCompleteness {
    pub(crate) panic: DomainCompleteness,
    pub(crate) safety: DomainCompleteness,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DomainCompleteness {
    pub(crate) complete: bool,
    pub(crate) visited_bodies: usize,
    pub(crate) reasons: Vec<IncompleteReason>,
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
    #[allow(
        dead_code,
        reason = "the typed safety authority begins emitting this boundary in the cutover slice"
    )]
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

/// Interprets only graph portions reachable from the supplied workspace roots.
#[cfg(test)]
#[must_use]
pub(crate) fn interpret(
    lookup: &dyn FunctionLookup,
    roots: &[InterpretationRoot],
    config: &SniffTestConfig,
) -> Vec<RootInterpretation> {
    roots
        .iter()
        .cloned()
        .map(|root| {
            let panic = DomainInterpreter::new(lookup, &root, config, EffectDomain::Panic).run();
            let safety = DomainInterpreter::new(lookup, &root, config, EffectDomain::Safety).run();
            let mut findings = panic.findings;
            findings.extend(safety.findings);
            RootInterpretation {
                root,
                findings,
                completeness: EffectCompleteness {
                    panic: panic.completeness,
                    safety: safety.completeness,
                },
            }
        })
        .collect()
}

/// Interprets only safety effects reachable from the supplied workspace roots.
#[must_use]
#[cfg(test)]
pub(crate) fn interpret_safety(
    lookup: &dyn FunctionLookup,
    roots: &[InterpretationRoot],
    config: &SniffTestConfig,
) -> Vec<SafetyRootInterpretation> {
    roots
        .iter()
        .cloned()
        .map(|root| {
            let safety = DomainInterpreter::new(lookup, &root, config, EffectDomain::Safety).run();
            SafetyRootInterpretation {
                root,
                findings: safety.findings,
                completeness: safety.completeness,
            }
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum EffectDomain {
    Panic,
    Safety,
}

#[derive(Debug)]
struct DomainResult {
    findings: Vec<InterpretedFinding>,
    completeness: DomainCompleteness,
}

#[derive(Debug, Clone)]
struct PendingVisit {
    function: FunctionId,
    preferred_scope: BodyScope,
    path: String,
    source_range: Option<SourceRangeIr>,
    satisfactions: SatisfactionState,
    trace: TracePath,
}

#[derive(Debug, Clone)]
struct PendingCall {
    body: Rc<FunctionBodyIr>,
    body_scope: BodyScope,
    call_index: usize,
    satisfactions: SatisfactionState,
    trace: TracePath,
    opaque_consumer_safety: bool,
}

#[derive(Debug, Clone)]
struct PendingResolvedCallable {
    call: PendingCall,
    key: CallableKeyIr,
    evidence: CallableTargetEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CallableTargetEvidence {
    target: FunctionTargetIr,
    scope: BodyScope,
}

struct ResolvedCallContext {
    target_scope: BodyScope,
    facts: ReconciledCallFacts,
}

#[derive(Debug, Clone)]
struct ReconciledCallFacts {
    fact_scope: BodyScope,
    call_site: CallSiteId,
    effect_group: Option<SafetyEffectGroupId>,
    inside_builtin_unsafe: bool,
    /// Source-contract target retained from unresolved or dynamic THIR
    /// dispatch. This carries the declared contract when a consumer later
    /// resolves the runtime edge to a concrete impl.
    source_target: Option<FunctionTargetIr>,
    defining_target: Option<FunctionTargetIr>,
}

#[derive(Debug, Clone)]
enum TraversalAction {
    Visit(PendingVisit),
    Call(PendingCall),
    ResolvedCallable(Box<PendingResolvedCallable>),
}

/// One persistent trace cursor into `DomainInterpreter::trace_nodes`.
///
/// Extending a path allocates one node regardless of its depth. Findings
/// materialize the linked path only when they need a public trace.
#[derive(Debug, Clone, Copy, Default)]
struct TracePath {
    tail: Option<usize>,
    len: usize,
}

#[derive(Debug)]
struct TraceNode {
    parent: Option<usize>,
    step: InterpretedTraceStep,
}

impl TracePath {
    fn push(&mut self, arena: &mut Vec<TraceNode>, step: InterpretedTraceStep) {
        arena.push(TraceNode {
            parent: self.tail,
            step,
        });
        self.tail = Some(arena.len() - 1);
        self.len += 1;
    }

    fn to_interpreted(self, arena: &[TraceNode]) -> InterpretedTrace {
        let mut steps = Vec::with_capacity(self.len);
        let mut current = self.tail;
        while let Some(index) = current {
            let node = &arena[index];
            steps.push(node.step.clone());
            current = node.parent;
        }
        steps.reverse();
        InterpretedTrace { steps }
    }
}

struct DomainInterpreter<'a> {
    lookup: &'a dyn FunctionLookup,
    root: &'a InterpretationRoot,
    config: &'a SniffTestConfig,
    domain: EffectDomain,
    findings: Vec<InterpretedFinding>,
    finding_keys: HashSet<FindingKey>,
    marker_claims: BTreeMap<MarkerClaimKey, MarkerClaim>,
    visited: HashSet<VisitKey>,
    completeness: DomainCompleteness,
    actions: Vec<TraversalAction>,
    trace_nodes: Vec<TraceNode>,
    callable_targets: BTreeMap<CallableKeyIr, Vec<CallableTargetEvidence>>,
    pending_callable_calls: BTreeMap<CallableKeyIr, Vec<PendingCall>>,
    scheduled_callable_edges: HashSet<CallableResolutionKey>,
}

impl<'a> DomainInterpreter<'a> {
    fn new(
        lookup: &'a dyn FunctionLookup,
        root: &'a InterpretationRoot,
        config: &'a SniffTestConfig,
        domain: EffectDomain,
    ) -> Self {
        Self {
            lookup,
            root,
            config,
            domain,
            findings: Vec::new(),
            finding_keys: HashSet::new(),
            marker_claims: BTreeMap::new(),
            visited: HashSet::new(),
            completeness: DomainCompleteness {
                complete: true,
                visited_bodies: 0,
                reasons: Vec::new(),
            },
            actions: Vec::new(),
            trace_nodes: Vec::new(),
            callable_targets: BTreeMap::new(),
            pending_callable_calls: BTreeMap::new(),
            scheduled_callable_edges: HashSet::new(),
        }
    }

    fn run(mut self) -> DomainResult {
        let Some(root_body) = self.lookup.function(self.root.function) else {
            self.missing_body(
                self.root.function,
                self.root.path.clone(),
                None,
                InterpretedTrace { steps: Vec::new() },
            );
            return self.finish();
        };
        let root_scope = root_body.scope().clone();
        let root_body = root_body.body().clone();

        if !self.root_is_boundary(&root_body, &root_scope) {
            self.schedule_visit(
                self.root.function,
                &root_scope,
                self.root.path.clone(),
                None,
                SatisfactionState::default(),
                TracePath::default(),
            );
            self.drain_actions();
        }
        self.finish()
    }

    fn drain_actions(&mut self) {
        // Calls are scheduled in reverse source order so this LIFO worklist
        // traverses them depth-first in source order.
        while let Some(action) = self.actions.pop() {
            match action {
                TraversalAction::Visit(visit) => self.visit(visit),
                TraversalAction::Call(call) => self.process_call(&call),
                TraversalAction::ResolvedCallable(call) => {
                    self.process_resolved_callable(&call);
                }
            }
        }
    }

    fn schedule_visit(
        &mut self,
        function: FunctionId,
        preferred_scope: &BodyScope,
        path: String,
        source_range: Option<SourceRangeIr>,
        satisfactions: SatisfactionState,
        trace: TracePath,
    ) {
        self.actions.push(TraversalAction::Visit(PendingVisit {
            function,
            preferred_scope: preferred_scope.clone(),
            path,
            source_range,
            satisfactions,
            trace,
        }));
    }

    fn finish(mut self) -> DomainResult {
        self.emit_ambiguous_marker_findings();
        DomainResult {
            findings: self.findings,
            completeness: self.completeness,
        }
    }

    fn root_is_boundary(&mut self, body: &FunctionBodyIr, body_scope: &BodyScope) -> bool {
        match self.domain {
            EffectDomain::Panic => {
                if self
                    .config
                    .panics
                    .ignores_candidates(&body.attributes.namespace_candidates)
                {
                    return true;
                }
                let contract = self.body_contract(body, EffectDomain::Panic);
                if let Some(contract) = &contract {
                    let trace = TracePath::default();
                    self.record_ambiguous_requirements(body, body_scope, contract, None, &trace);
                    // A selected root's own declaration describes its effects
                    // to callers; there is no entering call edge to report as
                    // an obligation within this root analysis.
                    return true;
                }
                self.config
                    .panics
                    .panic_boundary_policy_candidates(&body.attributes.namespace_candidates)
                    == PanicBoundaryPolicy::TrustedBoundary
            }
            EffectDomain::Safety => {
                if self
                    .config
                    .safety
                    .ignores_candidates(&body.attributes.namespace_candidates)
                {
                    return true;
                }
                let contract = self.body_contract(body, EffectDomain::Safety);
                // Missing API documentation is deliberately root-scoped,
                // matching report-root selection. Reached unsafe functions
                // are checked at their call sites instead.
                if body.attributes.is_exported && body.attributes.is_unsafe && contract.is_none() {
                    self.push_finding(
                        FindingEndpoint::Function(ScopedFunctionId::new(body_scope, body.function)),
                        InterpretedFindingKind::MissingSafetyDocs,
                        body,
                        None,
                        body.source_range.clone(),
                        InterpretedTrace { steps: Vec::new() },
                        Vec::new(),
                        Vec::new(),
                    );
                }
                if let Some(contract) = &contract {
                    let trace = TracePath::default();
                    self.record_ambiguous_requirements(body, body_scope, contract, None, &trace);
                    return true;
                }
                self.config
                    .safety
                    .trusts_safety_boundary_candidates(&body.attributes.namespace_candidates)
            }
        }
    }

    fn visit(&mut self, pending: PendingVisit) {
        let Some(body) = self
            .lookup
            .resolve(&pending.preferred_scope, pending.function)
        else {
            if self
                .lookup
                .manages_stable_crate_id(pending.function.def_path_hash.stable_crate_id())
            {
                self.missing_body(
                    pending.function,
                    pending.path,
                    pending.source_range,
                    pending.trace.to_interpreted(&self.trace_nodes),
                );
            }
            return;
        };
        let body_scope = body.scope().clone();
        let body = body.body().clone();
        let visit = VisitKey {
            function: ScopedFunctionId::new(&body_scope, body.function),
            satisfactions: pending.satisfactions.signature(),
        };
        if self.visited.contains(&visit) {
            return;
        }
        if self.ignores(&body.attributes) {
            self.visited.insert(visit);
            return;
        }
        if self.completeness.visited_bodies >= self.config.analysis.node_limit {
            self.node_limit();
            return;
        }

        self.visited.insert(visit);
        self.completeness.visited_bodies += 1;
        let is_consumer_overlay = matches!(
            body.provenance,
            FunctionBodyProvenanceIr::ConsumerInstantiation { .. }
        );
        let defining_body = (is_consumer_overlay && self.domain == EffectDomain::Safety)
            .then(|| self.lookup.defining_source_body(body.function))
            .flatten();
        // rustc can expose exact MIR for an unmanaged compiler-crate
        // instantiation even though no defining artifact can provide THIR
        // unsafe-scope facts. Its overlay-owned safety obligations are
        // intentionally opaque, but its dispatch edges can still lead back
        // into managed workspace closures or implementations.
        let opaque_consumer_safety =
            is_consumer_overlay && self.domain == EffectDomain::Safety && defining_body.is_none();
        if opaque_consumer_safety
            && body.attributes.has_rust_body
            && self
                .lookup
                .manages_stable_crate_id(body.function.def_path_hash.stable_crate_id())
        {
            self.missing_body(
                body.function,
                pending.path.clone(),
                pending.source_range.clone(),
                pending.trace.to_interpreted(&self.trace_nodes),
            );
        }
        if !opaque_consumer_safety {
            self.interpret_effects(&body, &body_scope, &pending.satisfactions, &pending.trace);
            if let Some(defining_body) = defining_body {
                self.interpret_defining_unsafe_effects(
                    defining_body.body(),
                    defining_body.scope(),
                    &pending.satisfactions,
                    &pending.trace,
                );
            }
        }
        let active_attribution = self.active_attribution();
        let collect_callable_evidence = active_attribution == CallableAttributionIr::CallSites;
        let body = Rc::new(body);
        for (call_index, _) in body.calls.iter().enumerate().rev().filter(|(_, call)| {
            call.applicable_attribution.contains(&active_attribution)
                || (collect_callable_evidence && is_callable_target_evidence(call))
        }) {
            self.actions.push(TraversalAction::Call(PendingCall {
                body: Rc::clone(&body),
                body_scope: body_scope.clone(),
                call_index,
                satisfactions: pending.satisfactions.clone(),
                trace: pending.trace,
                opaque_consumer_safety,
            }));
        }
    }

    fn process_call(&mut self, pending: &PendingCall) {
        let call = &pending.body.calls[pending.call_index];
        if self.active_attribution() == CallableAttributionIr::CallSites {
            if is_callable_target_evidence(call) {
                self.register_callable_target(pending);
                return;
            }
            if is_callable_invocation(call) {
                self.register_callable_call(pending);
            }
        }
        if pending.opaque_consumer_safety {
            self.follow_managed_safety_target(
                &pending.body,
                &pending.body_scope,
                &pending.body_scope,
                call,
                &pending.satisfactions,
                &pending.trace,
            );
        } else {
            self.interpret_call(
                &pending.body,
                &pending.body_scope,
                call,
                &pending.satisfactions,
                &pending.trace,
            );
        }
    }

    fn register_callable_target(&mut self, pending: &PendingCall) {
        let call = &pending.body.calls[pending.call_index];
        let CallTargetIr::Function(target) = &call.target else {
            return;
        };
        let evidence = CallableTargetEvidence {
            target: target.clone(),
            scope: pending.body_scope.clone(),
        };
        for key in &call.callable_keys {
            let is_new = {
                let targets = self.callable_targets.entry(*key).or_default();
                if targets.contains(&evidence) {
                    false
                } else {
                    targets.push(evidence.clone());
                    true
                }
            };
            if !is_new {
                continue;
            }
            let calls = self
                .pending_callable_calls
                .get(key)
                .cloned()
                .unwrap_or_default();
            for call in calls {
                self.schedule_resolved_callable(call, *key, evidence.clone());
            }
        }
    }

    fn register_callable_call(&mut self, pending: &PendingCall) {
        let call = &pending.body.calls[pending.call_index];
        for key in &call.callable_keys {
            self.pending_callable_calls
                .entry(*key)
                .or_default()
                .push(pending.clone());
            let targets = self.callable_targets.get(key).cloned().unwrap_or_default();
            for target in targets {
                self.schedule_resolved_callable(pending.clone(), *key, target);
            }
        }
    }

    fn schedule_resolved_callable(
        &mut self,
        call: PendingCall,
        key: CallableKeyIr,
        evidence: CallableTargetEvidence,
    ) {
        let source = &call.body.calls[call.call_index];
        let resolution = CallableResolutionKey {
            caller: ScopedFunctionId::new(&call.body_scope, call.body.function),
            call: source.id,
            satisfactions: call.satisfactions.signature(),
            target: evidence.target.function,
            target_scope: evidence.scope.clone(),
        };
        if self.scheduled_callable_edges.insert(resolution) {
            self.actions
                .push(TraversalAction::ResolvedCallable(Box::new(
                    PendingResolvedCallable {
                        call,
                        key,
                        evidence,
                    },
                )));
        }
    }

    fn process_resolved_callable(&mut self, pending: &PendingResolvedCallable) {
        let raw_call = &pending.call.body.calls[pending.call.call_index];
        let context = ResolvedCallContext {
            target_scope: pending.evidence.scope.clone(),
            facts: self.reconciled_call_facts(
                &pending.call.body,
                &pending.call.body_scope,
                raw_call,
            ),
        };
        let mut call = raw_call.clone();
        call.kind = match pending.key {
            CallableKeyIr::FnPointer(_) => CallEdgeKindIr::FnPointerCallTarget,
            CallableKeyIr::DynDispatch(_) => CallEdgeKindIr::DynDispatchVTableEntry,
        };
        call.applicable_attribution = vec![CallableAttributionIr::CallSites];
        call.callable_keys = vec![pending.key];
        call.target = CallTargetIr::Function(pending.evidence.target.clone());
        if pending.call.opaque_consumer_safety {
            self.follow_managed_safety_target(
                &pending.call.body,
                &pending.call.body_scope,
                &context.target_scope,
                &call,
                &pending.call.satisfactions,
                &pending.call.trace,
            );
        } else {
            self.interpret_call_with_context(
                &pending.call.body,
                &pending.call.body_scope,
                &call,
                &pending.call.satisfactions,
                &pending.call.trace,
                Some(&context),
            );
        }
    }

    fn interpret_effects(
        &mut self,
        body: &FunctionBodyIr,
        body_scope: &BodyScope,
        path_satisfactions: &SatisfactionState,
        trace: &TracePath,
    ) {
        for effect in &body.effects {
            match (&self.domain, &effect.kind) {
                (EffectDomain::Panic, EffectKindIr::CompilerAssert { kind, .. })
                    if !self.suppresses_safety_precondition_assert(body, *kind) =>
                {
                    let mut effect_trace = *trace;
                    let (caller, caller_path) = append_macro_expansion_steps(
                        &mut self.trace_nodes,
                        &mut effect_trace,
                        body,
                        CallId::new(effect.id.index()),
                        &effect.macro_expansions,
                    );
                    effect_trace.push(
                        &mut self.trace_nodes,
                        InterpretedTraceStep {
                            caller,
                            caller_path,
                            call: CallId::new(effect.id.index()),
                            kind: InterpretedTraceStepKind::Reachability(CallEdgeKindIr::Assert),
                            source_range: effect
                                .expanded_range
                                .clone()
                                .or_else(|| effect.source_range.clone()),
                            target: None,
                            target_path: Some(format!(
                                "compiler assert {}",
                                kind.human_description()
                            )),
                        },
                    );
                    let satisfactions = self.satisfactions_for(
                        body,
                        body_scope,
                        &MarkerTargetIr::Effect(effect.id),
                        path_satisfactions,
                    );
                    let endpoint = FindingEndpoint::Effect(
                        ScopedFunctionId::new(body_scope, body.function),
                        effect.id,
                    );
                    self.claim_markers(
                        &[],
                        &satisfactions,
                        &endpoint,
                        body_scope,
                        None,
                        None,
                        &effect_trace,
                    );
                }
                (EffectDomain::Safety, EffectKindIr::UnsafeOperation { kind }) => {
                    self.interpret_unsafe_effect(
                        body,
                        body_scope,
                        effect,
                        *kind,
                        path_satisfactions,
                        trace,
                    );
                }
                (
                    EffectDomain::Panic,
                    EffectKindIr::CompilerAssert { .. } | EffectKindIr::UnsafeOperation { .. },
                )
                | (EffectDomain::Safety, EffectKindIr::CompilerAssert { .. }) => {}
            }
        }
    }

    fn interpret_defining_unsafe_effects(
        &mut self,
        body: &FunctionBodyIr,
        body_scope: &BodyScope,
        path_satisfactions: &SatisfactionState,
        trace: &TracePath,
    ) {
        for effect in &body.effects {
            if let EffectKindIr::UnsafeOperation { kind } = effect.kind {
                self.interpret_unsafe_effect(
                    body,
                    body_scope,
                    effect,
                    kind,
                    path_satisfactions,
                    trace,
                );
            }
        }
    }

    fn interpret_unsafe_effect(
        &mut self,
        body: &FunctionBodyIr,
        body_scope: &BodyScope,
        effect: &super::ir::EffectFactIr,
        kind: SafetyOpKind,
        path_satisfactions: &SatisfactionState,
        trace: &TracePath,
    ) {
        let mut effect_trace = *trace;
        let (caller, caller_path) = append_macro_expansion_steps(
            &mut self.trace_nodes,
            &mut effect_trace,
            body,
            CallId::new(effect.id.index()),
            &effect.macro_expansions,
        );
        effect_trace.push(
            &mut self.trace_nodes,
            InterpretedTraceStep {
                caller,
                caller_path,
                call: CallId::new(effect.id.index()),
                kind: InterpretedTraceStepKind::UnsafeOperation(kind),
                source_range: effect
                    .expanded_range
                    .clone()
                    .or_else(|| effect.source_range.clone()),
                target: None,
                target_path: Some(format!("unsafe operation ({})", kind.label())),
            },
        );
        let satisfactions = self.satisfactions_for(
            body,
            body_scope,
            &MarkerTargetIr::Effect(effect.id),
            path_satisfactions,
        );
        let endpoint =
            FindingEndpoint::Effect(ScopedFunctionId::new(body_scope, body.function), effect.id);
        self.claim_markers(
            &[],
            &satisfactions,
            &endpoint,
            body_scope,
            None,
            effect.safety_effect_group,
            &effect_trace,
        );
        if missing_requirements(&[], &satisfactions).is_some() {
            self.push_finding(
                endpoint,
                InterpretedFindingKind::UnsafeOperation { kind },
                body,
                None,
                effect.source_range.clone(),
                effect_trace.to_interpreted(&self.trace_nodes),
                Vec::new(),
                Vec::new(),
            );
        }
    }

    fn interpret_call(
        &mut self,
        body: &FunctionBodyIr,
        body_scope: &BodyScope,
        call: &CallEdgeIr,
        path_satisfactions: &SatisfactionState,
        trace: &TracePath,
    ) {
        self.interpret_call_with_context(body, body_scope, call, path_satisfactions, trace, None);
    }

    fn interpret_call_with_context(
        &mut self,
        body: &FunctionBodyIr,
        body_scope: &BodyScope,
        call: &CallEdgeIr,
        path_satisfactions: &SatisfactionState,
        trace: &TracePath,
        resolved: Option<&ResolvedCallContext>,
    ) {
        if is_duplicate_bridge(call.kind) {
            return;
        }
        let (metadata, opaque_description) = call_target(call);
        let opaque_description =
            opaque_description.map(|description| opaque_call_description(call, description));
        let target = interpreted_target(metadata, opaque_description.as_deref());
        let mut next_trace = *trace;
        let (caller, caller_path) = append_macro_expansion_steps(
            &mut self.trace_nodes,
            &mut next_trace,
            body,
            call.id,
            &call.macro_expansions,
        );
        next_trace.push(
            &mut self.trace_nodes,
            InterpretedTraceStep {
                caller,
                caller_path,
                call: call.id,
                kind: InterpretedTraceStepKind::Reachability(call.kind),
                source_range: call
                    .expanded_range
                    .clone()
                    .or_else(|| call.source_range.clone()),
                target: metadata.map(|target| target.function),
                target_path: target.as_ref().map(|target| target.path.clone()),
            },
        );
        let satisfactions = self.satisfactions_for_call(body, body_scope, call, path_satisfactions);

        match self.domain {
            EffectDomain::Panic => self.interpret_panic_call(
                body,
                body_scope,
                resolved,
                call,
                metadata,
                opaque_description.as_deref(),
                target,
                &satisfactions,
                next_trace,
            ),
            EffectDomain::Safety => self.interpret_safety_call(
                body,
                body_scope,
                resolved,
                call,
                metadata,
                opaque_description.as_deref(),
                target,
                &satisfactions,
                next_trace,
            ),
        }
    }

    fn follow_managed_safety_target(
        &mut self,
        body: &FunctionBodyIr,
        body_scope: &BodyScope,
        target_scope: &BodyScope,
        call: &CallEdgeIr,
        path_satisfactions: &SatisfactionState,
        trace: &TracePath,
    ) {
        if is_duplicate_bridge(call.kind) {
            return;
        }
        let (Some(metadata), None) = call_target(call) else {
            return;
        };
        // A consumer overlay is opaque for its own safety facts, but it can
        // relay dispatch through further overlays until traversal reaches a
        // defining body owned by the composed analysis. A managed target with
        // an omitted body must still be scheduled so `visit` records the
        // incomplete artifact IR.
        let target_is_managed = self
            .lookup
            .manages_stable_crate_id(metadata.function.def_path_hash.stable_crate_id());
        let target_body_is_traversable = self
            .lookup
            .resolve(target_scope, metadata.function)
            .is_some_and(|body| {
                matches!(
                    body.body().provenance,
                    FunctionBodyProvenanceIr::DefiningArtifact
                        | FunctionBodyProvenanceIr::ConsumerInstantiation { .. }
                )
            })
            || self.lookup.defining_body(metadata.function).is_some();
        if (!target_body_is_traversable && !target_is_managed)
            || metadata.attributes.is_foreign
            || !metadata.attributes.has_rust_body
            || self
                .config
                .safety
                .ignores_candidates(&metadata.attributes.namespace_candidates)
            || self
                .config
                .safety
                .trusts_safety_boundary_candidates(&metadata.attributes.namespace_candidates)
            || self
                .target_contract(metadata, EffectDomain::Safety)
                .is_some()
        {
            return;
        }

        let mut next_trace = *trace;
        let (caller, caller_path) = append_macro_expansion_steps(
            &mut self.trace_nodes,
            &mut next_trace,
            body,
            call.id,
            &call.macro_expansions,
        );
        next_trace.push(
            &mut self.trace_nodes,
            InterpretedTraceStep {
                caller,
                caller_path,
                call: call.id,
                kind: InterpretedTraceStepKind::Reachability(call.kind),
                source_range: call
                    .expanded_range
                    .clone()
                    .or_else(|| call.source_range.clone()),
                target: Some(metadata.function),
                target_path: Some(metadata.display_path.clone()),
            },
        );
        let satisfactions = self.satisfactions_for(
            body,
            body_scope,
            &MarkerTargetIr::Call(call.id),
            path_satisfactions,
        );
        self.schedule_visit(
            metadata.function,
            target_scope,
            metadata.display_path.clone(),
            call.source_range.clone(),
            satisfactions,
            next_trace,
        );
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the panic-boundary decision table is clearer as one ordered policy operation"
    )]
    fn interpret_panic_call(
        &mut self,
        body: &FunctionBodyIr,
        body_scope: &BodyScope,
        resolved: Option<&ResolvedCallContext>,
        call: &CallEdgeIr,
        metadata: Option<&FunctionTargetIr>,
        opaque_description: Option<&str>,
        target: Option<InterpretedTarget>,
        satisfactions: &SatisfactionState,
        trace: TracePath,
    ) {
        let facts = resolved.map_or_else(
            || self.reconciled_call_facts(body, body_scope, call),
            |resolved| resolved.facts.clone(),
        );
        let runtime_metadata = metadata;
        let Some(metadata) = runtime_metadata
            .or(facts.defining_target.as_ref())
            .or(facts.source_target.as_ref())
        else {
            if opaque_description.is_some() && is_actual_call(call.kind) {
                self.push_terminal_call(
                    body,
                    body_scope,
                    resolved,
                    call,
                    target,
                    InterpretedFindingKind::OpaquePanicBoundary {
                        description: opaque_description
                            .unwrap_or("opaque call boundary")
                            .to_owned(),
                    },
                    &[],
                    satisfactions,
                    trace,
                );
            }
            return;
        };
        if self
            .config
            .panics
            .ignores_candidates(&metadata.attributes.namespace_candidates)
        {
            return;
        }

        let policy = self
            .config
            .panics
            .panic_boundary_policy_candidates(&metadata.attributes.namespace_candidates);
        let contract = self.call_contract(&facts, runtime_metadata, EffectDomain::Panic);
        if policy == PanicBoundaryPolicy::PanicSink {
            self.push_terminal_call(
                body,
                body_scope,
                resolved,
                call,
                target,
                InterpretedFindingKind::PanicSink,
                &[],
                satisfactions,
                trace,
            );
            return;
        }
        if let Some(contract) = contract {
            self.record_ambiguous_requirements(
                body,
                body_scope,
                &contract,
                target.as_ref(),
                &trace,
            );
            self.push_terminal_call(
                body,
                body_scope,
                resolved,
                call,
                target,
                InterpretedFindingKind::DocumentedPanic {
                    trusted: policy == PanicBoundaryPolicy::TrustedBoundary,
                },
                &contract.requirements,
                satisfactions,
                trace,
            );
            return;
        }
        if policy == PanicBoundaryPolicy::TrustedBoundary {
            return;
        }
        if metadata.attributes.is_foreign {
            return;
        }
        if !metadata.attributes.has_rust_body {
            if is_actual_call(call.kind) {
                self.push_terminal_call(
                    body,
                    body_scope,
                    resolved,
                    call,
                    target,
                    InterpretedFindingKind::OpaquePanicBoundary {
                        description: format!(
                            "indirect call to undocumented trait method `{}`",
                            metadata.display_path
                        ),
                    },
                    &[],
                    satisfactions,
                    trace,
                );
            }
            return;
        }
        if opaque_description.is_some() {
            if is_actual_call(call.kind) {
                self.push_terminal_call(
                    body,
                    body_scope,
                    resolved,
                    call,
                    target,
                    InterpretedFindingKind::OpaquePanicBoundary {
                        description: opaque_description
                            .unwrap_or("opaque call boundary")
                            .to_owned(),
                    },
                    &[],
                    satisfactions,
                    trace,
                );
            }
            return;
        }
        self.schedule_visit(
            metadata.function,
            resolved.map_or(body_scope, |resolved| &resolved.target_scope),
            metadata.display_path.clone(),
            call.source_range.clone(),
            satisfactions.clone(),
            trace,
        );
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the safety-boundary policy and trust provenance stay visible as one ordered decision table"
    )]
    fn interpret_safety_call(
        &mut self,
        body: &FunctionBodyIr,
        body_scope: &BodyScope,
        resolved: Option<&ResolvedCallContext>,
        call: &CallEdgeIr,
        metadata: Option<&FunctionTargetIr>,
        opaque_description: Option<&str>,
        target: Option<InterpretedTarget>,
        satisfactions: &SatisfactionState,
        trace: TracePath,
    ) {
        let facts = resolved.map_or_else(
            || self.reconciled_call_facts(body, body_scope, call),
            |resolved| resolved.facts.clone(),
        );
        let runtime_metadata = metadata;
        let metadata = runtime_metadata
            .or(facts.defining_target.as_ref())
            .or(facts.source_target.as_ref());
        if let Some(metadata) = metadata
            && self
                .config
                .safety
                .ignores_candidates(&metadata.attributes.namespace_candidates)
        {
            return;
        }

        let inside_builtin_unsafe = facts.inside_builtin_unsafe;
        let contract = self.call_contract(&facts, runtime_metadata, EffectDomain::Safety);
        if let (Some(metadata), Some(contract)) = (metadata, contract) {
            if inside_builtin_unsafe {
                return;
            }
            let trusted = self
                .config
                .safety
                .trusts_safety_boundary_candidates(&metadata.attributes.namespace_candidates);
            self.record_ambiguous_requirements(
                body,
                body_scope,
                &contract,
                target.as_ref(),
                &trace,
            );
            if call.requires_unsafe && is_actual_call(call.kind) {
                self.push_terminal_call(
                    body,
                    body_scope,
                    resolved,
                    call,
                    target,
                    InterpretedFindingKind::SafetyCall {
                        kind: InterpretedSafetyCallKind::Unsafe,
                        trusted,
                    },
                    &contract.requirements,
                    satisfactions,
                    trace,
                );
            } else if !metadata.attributes.is_unsafe {
                self.push_terminal_call(
                    body,
                    body_scope,
                    resolved,
                    call,
                    target,
                    InterpretedFindingKind::SafetyCall {
                        kind: InterpretedSafetyCallKind::Obligation,
                        trusted,
                    },
                    &contract.requirements,
                    satisfactions,
                    trace,
                );
            }
            return;
        }
        if metadata.is_some_and(|metadata| {
            self.config
                .safety
                .trusts_safety_boundary_candidates(&metadata.attributes.namespace_candidates)
        }) {
            return;
        }

        if !inside_builtin_unsafe && call.requires_unsafe && is_actual_call(call.kind) {
            self.push_terminal_call(
                body,
                body_scope,
                resolved,
                call,
                target,
                InterpretedFindingKind::SafetyCall {
                    kind: InterpretedSafetyCallKind::Unsafe,
                    trusted: false,
                },
                &[],
                satisfactions,
                trace,
            );
        }
        if metadata.is_some_and(|metadata| {
            metadata.attributes.is_foreign || !metadata.attributes.has_rust_body
        }) {
            return;
        }
        if opaque_description.is_none()
            && let Some(metadata) = metadata
        {
            self.schedule_visit(
                metadata.function,
                resolved.map_or(body_scope, |resolved| &resolved.target_scope),
                metadata.display_path.clone(),
                call.source_range.clone(),
                satisfactions.clone(),
                trace,
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn push_terminal_call(
        &mut self,
        body: &FunctionBodyIr,
        body_scope: &BodyScope,
        resolved: Option<&ResolvedCallContext>,
        call: &CallEdgeIr,
        target: Option<InterpretedTarget>,
        kind: InterpretedFindingKind,
        requirements: &[ContractRequirementIr],
        satisfactions: &SatisfactionState,
        trace: TracePath,
    ) {
        let endpoint = FindingEndpoint::Call(
            ScopedFunctionId::new(body_scope, body.function),
            call.id,
            callable_resolution_target(call),
        );
        let facts = resolved.map_or_else(
            || self.reconciled_call_facts(body, body_scope, call),
            |resolved| resolved.facts.clone(),
        );
        self.claim_markers(
            requirements,
            satisfactions,
            &endpoint,
            &facts.fact_scope,
            Some(facts.call_site),
            facts.effect_group,
            &trace,
        );
        let Some(missing) = missing_requirements(requirements, satisfactions) else {
            return;
        };
        self.push_finding(
            endpoint,
            kind,
            body,
            target,
            call.source_range.clone(),
            trace.to_interpreted(&self.trace_nodes),
            missing,
            requirements.to_vec(),
        );
    }

    fn reconciled_call_facts(
        &self,
        body: &FunctionBodyIr,
        body_scope: &BodyScope,
        call: &CallEdgeIr,
    ) -> ReconciledCallFacts {
        let fallback = ReconciledCallFacts {
            fact_scope: body_scope.clone(),
            call_site: call.call_site,
            effect_group: call.safety_effect_group,
            inside_builtin_unsafe: call.inside_builtin_unsafe,
            source_target: call.source_target.clone(),
            defining_target: None,
        };
        if !matches!(
            body.provenance,
            FunctionBodyProvenanceIr::ConsumerInstantiation { .. }
        ) {
            return fallback;
        }
        let Some(defining_body) = self.lookup.defining_source_body(body.function) else {
            return fallback;
        };
        let active_attribution = self.active_attribution();
        let candidates = matching_definition_calls(defining_body.body(), call, active_attribution);
        if candidates.is_empty() {
            return fallback;
        }
        let defining_call_site = shared_call_site(&candidates);
        let defining_effect_group = shared_safety_effect_group(&candidates);
        let uses_defining_scope = match self.domain {
            EffectDomain::Panic => defining_call_site.is_some(),
            EffectDomain::Safety => defining_effect_group.is_shared(),
        };
        let fact_scope = if uses_defining_scope {
            defining_body.scope().clone()
        } else {
            fallback.fact_scope.clone()
        };
        let source_target =
            shared_source_target(&candidates).or_else(|| fallback.source_target.clone());
        ReconciledCallFacts {
            fact_scope,
            call_site: defining_call_site.unwrap_or(fallback.call_site),
            effect_group: defining_effect_group
                .into_shared()
                .unwrap_or(fallback.effect_group),
            inside_builtin_unsafe: fallback.inside_builtin_unsafe
                || candidates
                    .iter()
                    .all(|candidate| candidate.inside_builtin_unsafe),
            source_target,
            defining_target: shared_definition_target(&candidates),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn push_finding(
        &mut self,
        endpoint: FindingEndpoint,
        kind: InterpretedFindingKind,
        body: &FunctionBodyIr,
        target: Option<InterpretedTarget>,
        source_range: Option<SourceRangeIr>,
        trace: InterpretedTrace,
        missing_requirements: Vec<ContractRequirementIr>,
        requirements: Vec<ContractRequirementIr>,
    ) {
        let key = FindingKey {
            endpoint,
            class: FindingClass::from_kind(&kind),
            missing: missing_requirements
                .iter()
                .map(|requirement| normalize_requirement_name(&requirement.name))
                .collect(),
        };
        if !self.finding_keys.insert(key) {
            return;
        }
        self.findings.push(InterpretedFinding {
            kind,
            function: body.function,
            function_path: body.display_path.clone(),
            target,
            source_range,
            trace,
            missing_requirements,
            requirements,
        });
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "marker claims need both semantic grouping identities and their trace evidence"
    )]
    fn claim_markers(
        &mut self,
        requirements: &[ContractRequirementIr],
        satisfactions: &SatisfactionState,
        endpoint: &FindingEndpoint,
        fact_scope: &BodyScope,
        call_site: Option<CallSiteId>,
        safety_effect_group: Option<SafetyEffectGroupId>,
        trace: &TracePath,
    ) {
        let effect_group = match (self.domain, call_site, safety_effect_group) {
            (EffectDomain::Panic, Some(call_site), _) => MarkerEffectGroup::CallSite {
                scope: fact_scope.clone(),
                call_site,
            },
            (EffectDomain::Safety, _, Some(group)) => MarkerEffectGroup::Safety {
                scope: fact_scope.clone(),
                group,
            },
            _ => MarkerEffectGroup::Endpoint(endpoint.clone()),
        };
        if !satisfactions
            .markers
            .iter()
            .any(|marker| marker_contributes(marker, requirements))
        {
            return;
        }
        let trace = trace.to_interpreted(&self.trace_nodes);
        for marker in satisfactions
            .markers
            .iter()
            .filter(|marker| marker_contributes(marker, requirements))
        {
            let claim = self
                .marker_claims
                .entry(marker.key.clone())
                .or_insert_with(|| MarkerClaim {
                    key: marker.key.clone(),
                    source_range: marker.source_range.clone(),
                    effect_groups: HashSet::new(),
                    trace: trace.clone(),
                });
            claim.effect_groups.insert(effect_group.clone());
            if canonical_marker_trace_order(&trace, &claim.trace).is_lt() {
                claim.trace = trace.clone();
            }
        }
    }

    fn emit_ambiguous_marker_findings(&mut self) {
        let claims = self
            .marker_claims
            .values()
            .filter(|claim| claim.effect_groups.len() > 1)
            .cloned()
            .collect::<Vec<_>>();
        for claim in claims {
            let Some(body) = self
                .lookup
                .function_in_scope(&claim.key.owner.scope, claim.key.owner.function)
            else {
                continue;
            };
            let body = body.body().clone();
            let effect_count = claim.effect_groups.len();
            let kind = match self.domain {
                EffectDomain::Panic => {
                    InterpretedFindingKind::AmbiguousPanicMarker { effect_count }
                }
                EffectDomain::Safety => {
                    InterpretedFindingKind::AmbiguousSafetyMarker { effect_count }
                }
            };
            self.push_finding(
                FindingEndpoint::Marker(claim.key.owner, claim.key.identity),
                kind,
                &body,
                None,
                claim.source_range,
                claim.trace,
                Vec::new(),
                Vec::new(),
            );
        }
    }

    fn record_ambiguous_requirements(
        &mut self,
        body: &FunctionBodyIr,
        body_scope: &BodyScope,
        contract: &EffectiveContract,
        target: Option<&InterpretedTarget>,
        trace: &TracePath,
    ) {
        for (normalized_name, requirements) in ambiguous_requirements(&contract.requirements) {
            let kind = match self.domain {
                EffectDomain::Panic => InterpretedFindingKind::AmbiguousPanicRequirement {
                    normalized_name: normalized_name.clone(),
                },
                EffectDomain::Safety => InterpretedFindingKind::AmbiguousSafetyRequirement {
                    normalized_name: normalized_name.clone(),
                },
            };
            let function = target
                .and_then(|target| target.function)
                .unwrap_or(body.function);
            let function_scope = target
                .and_then(|target| target.function)
                .and_then(|function| self.lookup.resolve(body_scope, function))
                .map_or_else(|| body_scope.clone(), |body| body.scope().clone());
            self.push_finding(
                FindingEndpoint::Ambiguous(
                    ScopedFunctionId {
                        scope: function_scope,
                        function,
                    },
                    normalized_name,
                ),
                kind,
                body,
                target.cloned(),
                contract.source_range.clone(),
                trace.to_interpreted(&self.trace_nodes),
                Vec::new(),
                requirements,
            );
        }
    }

    fn satisfactions_for(
        &self,
        body: &FunctionBodyIr,
        body_scope: &BodyScope,
        target: &MarkerTargetIr,
        path_satisfactions: &SatisfactionState,
    ) -> SatisfactionState {
        let marker_kind = match self.domain {
            EffectDomain::Panic => MarkerKindIr::PanicJustification,
            EffectDomain::Safety => MarkerKindIr::SafetyJustification,
        };
        let mut satisfactions = path_satisfactions.clone();
        for marker in body.markers.iter().filter(|marker| {
            marker.kind == marker_kind && &marker.target == target && self.marker_applies(marker)
        }) {
            satisfactions.add_marker(ScopedFunctionId::new(body_scope, body.function), marker);
        }
        satisfactions
    }

    fn satisfactions_for_call(
        &self,
        body: &FunctionBodyIr,
        body_scope: &BodyScope,
        call: &CallEdgeIr,
        path_satisfactions: &SatisfactionState,
    ) -> SatisfactionState {
        let mut satisfactions = self.satisfactions_for(
            body,
            body_scope,
            &MarkerTargetIr::Call(call.id),
            path_satisfactions,
        );
        if !matches!(
            body.provenance,
            FunctionBodyProvenanceIr::ConsumerInstantiation { .. }
        ) {
            return satisfactions;
        }
        let Some(defining_body) = self.lookup.defining_source_body(body.function) else {
            return satisfactions;
        };
        let candidates =
            matching_definition_calls(defining_body.body(), call, self.active_attribution());
        if candidates.is_empty() {
            return satisfactions;
        }
        let source_group_is_unambiguous = match self.domain {
            EffectDomain::Panic => shared_call_site(&candidates).is_some(),
            EffectDomain::Safety => shared_safety_effect_group(&candidates).is_shared(),
        };
        if !source_group_is_unambiguous {
            return satisfactions;
        }

        let marker_kind = match self.domain {
            EffectDomain::Panic => MarkerKindIr::PanicJustification,
            EffectDomain::Safety => MarkerKindIr::SafetyJustification,
        };
        let marker_owner =
            ScopedFunctionId::new(defining_body.scope(), defining_body.body().function);
        for marker in defining_body.body().markers.iter().filter(|marker| {
            marker.kind == marker_kind
                && self.marker_applies(marker)
                && matches!(
                    &marker.target,
                    MarkerTargetIr::Call(call_id)
                        if candidates.iter().any(|candidate| candidate.id == *call_id)
                )
        }) {
            satisfactions.add_marker(marker_owner.clone(), marker);
        }
        satisfactions
    }

    fn active_attribution(&self) -> CallableAttributionIr {
        match self.config.analysis.callable_edge_attribution {
            CallableEdgeAttribution::ErasureSites => CallableAttributionIr::ErasureSites,
            CallableEdgeAttribution::CallSites => CallableAttributionIr::CallSites,
        }
    }

    fn marker_applies(&self, marker: &MarkerIr) -> bool {
        let active = match self.config.analysis.marker_probing {
            MarkerProbing::SourceCallsite => MarkerProbingIr::SourceCallsite,
            MarkerProbing::MacroDefinitionFirst => MarkerProbingIr::MacroDefinitionFirst,
        };
        marker.applicable_probing.contains(&active)
    }

    fn ignores(&self, attributes: &FunctionAttributesIr) -> bool {
        match self.domain {
            EffectDomain::Panic => self
                .config
                .panics
                .ignores_candidates(&attributes.namespace_candidates),
            EffectDomain::Safety => self
                .config
                .safety
                .ignores_candidates(&attributes.namespace_candidates),
        }
    }

    fn body_contract(
        &self,
        body: &FunctionBodyIr,
        domain: EffectDomain,
    ) -> Option<EffectiveContract> {
        let marker_kind = match domain {
            EffectDomain::Panic => MarkerKindIr::PanicContract,
            EffectDomain::Safety => MarkerKindIr::SafetyContract,
        };
        let raw = body.markers.iter().find_map(|marker| {
            (marker.kind == marker_kind && marker.target == MarkerTargetIr::Function(body.function))
                .then(|| RawContractIr {
                    source_range: marker.source_range.clone(),
                    requirements: marker.requirements.clone(),
                })
        });
        self.effective_contract(&body.attributes.namespace_candidates, raw.as_ref(), domain)
    }

    fn target_contract(
        &self,
        target: &FunctionTargetIr,
        domain: EffectDomain,
    ) -> Option<EffectiveContract> {
        let raw = match domain {
            EffectDomain::Panic => target.contracts.panic.as_ref(),
            EffectDomain::Safety => target.contracts.safety.as_ref(),
        };
        self.effective_contract(&target.attributes.namespace_candidates, raw, domain)
    }

    fn call_contract(
        &self,
        facts: &ReconciledCallFacts,
        runtime_target: Option<&FunctionTargetIr>,
        domain: EffectDomain,
    ) -> Option<EffectiveContract> {
        if let Some(contract) = facts
            .source_target
            .as_ref()
            .and_then(|target| self.target_contract(target, domain))
        {
            return Some(contract);
        }
        match runtime_target {
            Some(target) => self.target_contract(target, domain),
            None => facts
                .defining_target
                .as_ref()
                .and_then(|target| self.target_contract(target, domain)),
        }
    }

    fn effective_contract(
        &self,
        candidates: &[String],
        raw: Option<&RawContractIr>,
        domain: EffectDomain,
    ) -> Option<EffectiveContract> {
        if let Some(markdown) = self
            .config
            .documentation
            .overrides
            .markdown_for_candidates(candidates)
        {
            let summary = match domain {
                EffectDomain::Panic => panic_contract_doc_summary_from_markdown(markdown),
                EffectDomain::Safety => safety_contract_doc_summary_from_markdown(markdown),
            };
            return summary.has_docs.then(|| EffectiveContract {
                source_range: None,
                requirements: summary
                    .requirements
                    .into_iter()
                    .map(|requirement| ContractRequirementIr {
                        name: requirement.name,
                        condition: requirement.condition,
                        source_range: None,
                    })
                    .collect(),
            });
        }
        raw.map(|contract| EffectiveContract {
            source_range: contract.source_range.clone(),
            requirements: contract.requirements.clone(),
        })
    }

    fn suppresses_safety_precondition_assert(
        &self,
        body: &FunctionBodyIr,
        kind: CompilerAssertKind,
    ) -> bool {
        body.attributes.is_unsafe
            && matches!(
                kind,
                CompilerAssertKind::NullPointerDereference
                    | CompilerAssertKind::MisalignedPointerDereference
                    | CompilerAssertKind::InvalidEnumConstruction
            )
            && self.body_contract(body, EffectDomain::Safety).is_some()
    }

    fn node_limit(&mut self) {
        self.completeness.complete = false;
        if !self
            .completeness
            .reasons
            .iter()
            .any(|reason| matches!(reason, IncompleteReason::NodeLimit { .. }))
        {
            self.completeness.reasons.push(IncompleteReason::NodeLimit {
                limit: self.config.analysis.node_limit,
            });
        }
    }

    fn missing_body(
        &mut self,
        function: FunctionId,
        path: String,
        source_range: Option<SourceRangeIr>,
        trace: InterpretedTrace,
    ) {
        self.completeness.complete = false;
        let reason = IncompleteReason::MissingBody {
            function,
            path,
            source_range,
            trace,
        };
        if !self.completeness.reasons.contains(&reason) {
            self.completeness.reasons.push(reason);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EffectiveContract {
    source_range: Option<SourceRangeIr>,
    requirements: Vec<ContractRequirementIr>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SatisfactionState {
    unnamed: bool,
    named: BTreeSet<String>,
    markers: Vec<AppliedMarker>,
}

impl SatisfactionState {
    fn add_marker(&mut self, owner: ScopedFunctionId, marker: &MarkerIr) {
        let mut applied = AppliedMarker {
            key: MarkerClaimKey {
                owner,
                identity: marker_identity(marker),
            },
            source_range: marker.source_range.clone(),
            unnamed: false,
            named: BTreeSet::new(),
        };
        for satisfaction in &marker.satisfactions {
            if satisfaction.reason.trim().is_empty() {
                continue;
            }
            if let Some(requirement) = &satisfaction.requirement {
                let requirement = normalize_requirement_name(requirement);
                self.named.insert(requirement.clone());
                applied.named.insert(requirement);
            } else {
                self.unnamed = true;
                applied.unnamed = true;
            }
        }
        if (applied.unnamed || !applied.named.is_empty())
            && !self
                .markers
                .iter()
                .any(|existing| existing.key == applied.key)
        {
            self.markers.push(applied);
            self.markers.sort_by(|left, right| left.key.cmp(&right.key));
        }
    }

    fn signature(&self) -> SatisfactionSignature {
        SatisfactionSignature {
            unnamed: self.unnamed,
            named: self.named.clone(),
            markers: self
                .markers
                .iter()
                .map(|marker| marker.key.clone())
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct ScopedFunctionId {
    scope: BodyScope,
    function: FunctionId,
}

impl ScopedFunctionId {
    fn new(scope: &BodyScope, function: FunctionId) -> Self {
        Self {
            scope: scope.clone(),
            function,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct VisitKey {
    function: ScopedFunctionId,
    satisfactions: SatisfactionSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CallableResolutionKey {
    caller: ScopedFunctionId,
    call: CallId,
    satisfactions: SatisfactionSignature,
    target: FunctionId,
    target_scope: BodyScope,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SatisfactionSignature {
    unnamed: bool,
    named: BTreeSet<String>,
    markers: Vec<MarkerClaimKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AppliedMarker {
    key: MarkerClaimKey,
    source_range: Option<SourceRangeIr>,
    unnamed: bool,
    named: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct MarkerClaimKey {
    owner: ScopedFunctionId,
    identity: String,
}

#[derive(Debug, Clone)]
struct MarkerClaim {
    key: MarkerClaimKey,
    source_range: Option<SourceRangeIr>,
    effect_groups: HashSet<MarkerEffectGroup>,
    trace: InterpretedTrace,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum MarkerEffectGroup {
    Endpoint(FindingEndpoint),
    CallSite {
        scope: BodyScope,
        call_site: CallSiteId,
    },
    Safety {
        scope: BodyScope,
        group: SafetyEffectGroupId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum FindingEndpoint {
    Function(ScopedFunctionId),
    Call(ScopedFunctionId, CallId, Option<FunctionId>),
    Effect(ScopedFunctionId, EffectId),
    Ambiguous(ScopedFunctionId, String),
    Marker(ScopedFunctionId, String),
}

fn callable_resolution_target(call: &CallEdgeIr) -> Option<FunctionId> {
    matches!(
        call.kind,
        CallEdgeKindIr::FnPointerCallTarget | CallEdgeKindIr::DynDispatchVTableEntry
    )
    .then(|| call_target(call).0.map(|target| target.function))
    .flatten()
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FindingKey {
    endpoint: FindingEndpoint,
    class: FindingClass,
    missing: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum FindingClass {
    PanicSink,
    DocumentedPanic(bool),
    OpaquePanicBoundary,
    MissingSafetyDocs,
    SafetyCall(InterpretedSafetyCallKind),
    OpaqueSafetyBoundary,
    UnsafeOperation,
    AmbiguousPanicRequirement,
    AmbiguousSafetyRequirement,
    AmbiguousPanicMarker,
    AmbiguousSafetyMarker,
}

impl FindingClass {
    fn from_kind(kind: &InterpretedFindingKind) -> Self {
        match kind {
            InterpretedFindingKind::PanicSink => Self::PanicSink,
            InterpretedFindingKind::DocumentedPanic { trusted } => Self::DocumentedPanic(*trusted),
            InterpretedFindingKind::OpaquePanicBoundary { .. } => Self::OpaquePanicBoundary,
            InterpretedFindingKind::MissingSafetyDocs => Self::MissingSafetyDocs,
            InterpretedFindingKind::SafetyCall { kind, .. } => Self::SafetyCall(*kind),
            InterpretedFindingKind::OpaqueSafetyBoundary { .. } => Self::OpaqueSafetyBoundary,
            InterpretedFindingKind::UnsafeOperation { .. } => Self::UnsafeOperation,
            InterpretedFindingKind::AmbiguousPanicRequirement { .. } => {
                Self::AmbiguousPanicRequirement
            }
            InterpretedFindingKind::AmbiguousSafetyRequirement { .. } => {
                Self::AmbiguousSafetyRequirement
            }
            InterpretedFindingKind::AmbiguousPanicMarker { .. } => Self::AmbiguousPanicMarker,
            InterpretedFindingKind::AmbiguousSafetyMarker { .. } => Self::AmbiguousSafetyMarker,
        }
    }
}

fn call_target(call: &CallEdgeIr) -> (Option<&FunctionTargetIr>, Option<&str>) {
    match &call.target {
        CallTargetIr::Function(target) => (Some(target), None),
        CallTargetIr::OpaqueBoundary {
            description,
            target,
        } => {
            let target = target.as_ref().map(|target| match target {
                OpaqueTargetIr::Trait(target) | OpaqueTargetIr::Function(target) => target,
            });
            (target, Some(description))
        }
    }
}

fn append_macro_expansion_steps(
    arena: &mut Vec<TraceNode>,
    trace: &mut TracePath,
    body: &FunctionBodyIr,
    call: CallId,
    frames: &[MacroExpansionFrameIr],
) -> (FunctionId, String) {
    let mut caller = body.function;
    let mut caller_path = body.display_path.clone();
    for frame in frames {
        let target = FunctionId::generic(frame.macro_def);
        let target_path = format!("macro {}", frame.display_path);
        trace.push(
            arena,
            InterpretedTraceStep {
                caller,
                caller_path,
                call,
                kind: InterpretedTraceStepKind::Reachability(CallEdgeKindIr::MacroExpansion),
                source_range: frame.source_range.clone(),
                target: Some(target),
                target_path: Some(target_path.clone()),
            },
        );
        caller = target;
        caller_path = target_path;
    }
    (caller, caller_path)
}

fn definition_call_matches(overlay: &CallEdgeIr, defining: &CallEdgeIr) -> bool {
    same_source_call(overlay, defining)
        && (call_target(overlay)
            .0
            .zip(call_target(defining).0)
            .is_some_and(|(overlay, defining)| {
                overlay.function.def_path_hash == defining.function.def_path_hash
            })
            || (overlay.kind == defining.kind
                && call_target_definitions_match(&overlay.target, &defining.target)))
}

fn same_source_call(overlay: &CallEdgeIr, defining: &CallEdgeIr) -> bool {
    overlay.expanded_range.is_some()
        && overlay.expanded_range == defining.expanded_range
        && overlay.callee_range == defining.callee_range
}

fn matching_definition_calls<'a>(
    defining_body: &'a FunctionBodyIr,
    overlay: &CallEdgeIr,
    active_attribution: CallableAttributionIr,
) -> Vec<&'a CallEdgeIr> {
    let source_candidates = defining_body
        .calls
        .iter()
        .filter(|candidate| {
            candidate
                .applicable_attribution
                .contains(&active_attribution)
                && same_source_call(overlay, candidate)
        })
        .collect::<Vec<_>>();
    let semantic_matches = source_candidates
        .iter()
        .copied()
        .filter(|candidate| definition_call_matches(overlay, candidate))
        .collect::<Vec<_>>();
    if !semantic_matches.is_empty() {
        return semantic_matches;
    }

    // Monomorphization can turn an opaque trait invocation into a concrete
    // direct call with a different definition identity. Fall back to the
    // stable source-call identity only when no semantic target match exists;
    // consensus checks on group/site identity keep ambiguous lowering
    // candidates conservative.
    source_candidates
        .into_iter()
        .filter(|candidate| is_actual_call(overlay.kind) && is_actual_call(candidate.kind))
        .collect()
}

fn shared_call_site(candidates: &[&CallEdgeIr]) -> Option<CallSiteId> {
    let first = candidates.first()?.call_site;
    candidates
        .iter()
        .all(|candidate| candidate.call_site == first)
        .then_some(first)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FactConsensus<T> {
    Shared(T),
    Ambiguous,
}

impl<T> FactConsensus<T> {
    const fn is_shared(&self) -> bool {
        matches!(self, Self::Shared(_))
    }

    fn into_shared(self) -> Option<T> {
        match self {
            Self::Shared(value) => Some(value),
            Self::Ambiguous => None,
        }
    }
}

fn shared_safety_effect_group(
    candidates: &[&CallEdgeIr],
) -> FactConsensus<Option<SafetyEffectGroupId>> {
    let Some(first) = candidates.first() else {
        return FactConsensus::Ambiguous;
    };
    let first = first.safety_effect_group;
    if candidates
        .iter()
        .all(|candidate| candidate.safety_effect_group == first)
    {
        FactConsensus::Shared(first)
    } else {
        FactConsensus::Ambiguous
    }
}

fn shared_definition_target(candidates: &[&CallEdgeIr]) -> Option<FunctionTargetIr> {
    let first = call_target(candidates.first()?).0?;
    candidates
        .iter()
        .skip(1)
        .all(|candidate| call_target(candidate).0 == Some(first))
        .then(|| first.clone())
}

fn shared_source_target(candidates: &[&CallEdgeIr]) -> Option<FunctionTargetIr> {
    let first = candidates.first()?.source_target.as_ref()?;
    candidates
        .iter()
        .skip(1)
        .all(|candidate| candidate.source_target.as_ref() == Some(first))
        .then(|| first.clone())
}

fn call_target_definitions_match(overlay: &CallTargetIr, defining: &CallTargetIr) -> bool {
    match (overlay, defining) {
        (CallTargetIr::Function(overlay), CallTargetIr::Function(defining)) => {
            overlay.function.def_path_hash == defining.function.def_path_hash
        }
        (
            CallTargetIr::OpaqueBoundary {
                description: overlay_description,
                target: overlay_target,
            },
            CallTargetIr::OpaqueBoundary {
                description: defining_description,
                target: defining_target,
            },
        ) => match (overlay_target, defining_target) {
            (Some(overlay), Some(defining)) => opaque_target_definitions_match(overlay, defining),
            (None, None) => overlay_description == defining_description,
            (Some(_), None) | (None, Some(_)) => false,
        },
        (CallTargetIr::Function(_), CallTargetIr::OpaqueBoundary { .. })
        | (CallTargetIr::OpaqueBoundary { .. }, CallTargetIr::Function(_)) => false,
    }
}

fn opaque_target_definitions_match(overlay: &OpaqueTargetIr, defining: &OpaqueTargetIr) -> bool {
    match (overlay, defining) {
        (OpaqueTargetIr::Trait(overlay), OpaqueTargetIr::Trait(defining))
        | (OpaqueTargetIr::Function(overlay), OpaqueTargetIr::Function(defining)) => {
            overlay.function.def_path_hash == defining.function.def_path_hash
        }
        (OpaqueTargetIr::Trait(_), OpaqueTargetIr::Function(_))
        | (OpaqueTargetIr::Function(_), OpaqueTargetIr::Trait(_)) => false,
    }
}

fn interpreted_target(
    metadata: Option<&FunctionTargetIr>,
    opaque_description: Option<&str>,
) -> Option<InterpretedTarget> {
    metadata
        .map(|target| InterpretedTarget {
            function: Some(target.function),
            path: target.display_path.clone(),
        })
        .or_else(|| {
            opaque_description.map(|description| InterpretedTarget {
                function: None,
                path: description.to_owned(),
            })
        })
}

fn opaque_call_description(call: &CallEdgeIr, description: &str) -> String {
    if call.kind != CallEdgeKindIr::IndirectCall {
        return description.to_owned();
    }
    if call.requires_unsafe {
        String::from("indirect call through an unsafe function pointer")
    } else {
        String::from("indirect call through a function pointer")
    }
}

fn is_duplicate_bridge(kind: CallEdgeKindIr) -> bool {
    matches!(
        kind,
        CallEdgeKindIr::MacroExpansion | CallEdgeKindIr::DynObjectCast | CallEdgeKindIr::Assert
    )
}

fn is_callable_target_evidence(call: &CallEdgeIr) -> bool {
    !call.callable_keys.is_empty()
        && matches!(
            call.kind,
            CallEdgeKindIr::FnPointerReify
                | CallEdgeKindIr::ClosureFnPointerReify
                | CallEdgeKindIr::VTableEntry
        )
}

fn is_callable_invocation(call: &CallEdgeIr) -> bool {
    !call.callable_keys.is_empty()
        && matches!(
            call.kind,
            CallEdgeKindIr::DirectCall | CallEdgeKindIr::TailCall | CallEdgeKindIr::IndirectCall
        )
}

fn is_actual_call(kind: CallEdgeKindIr) -> bool {
    matches!(
        kind,
        CallEdgeKindIr::DirectCall
            | CallEdgeKindIr::TailCall
            | CallEdgeKindIr::FnPointerCallTarget
            | CallEdgeKindIr::DynDispatchVTableEntry
            | CallEdgeKindIr::IndirectCall
    )
}

fn marker_identity(marker: &MarkerIr) -> String {
    marker.identity.clone()
}

fn marker_contributes(marker: &AppliedMarker, requirements: &[ContractRequirementIr]) -> bool {
    if requirements.is_empty() {
        return marker.unnamed;
    }
    requirements.iter().any(|requirement| {
        marker
            .named
            .contains(&normalize_requirement_name(&requirement.name))
    })
}

fn canonical_marker_trace_order(left: &InterpretedTrace, right: &InterpretedTrace) -> Ordering {
    left.steps.len().cmp(&right.steps.len()).then_with(|| {
        left.steps
            .iter()
            .zip(&right.steps)
            .find_map(|(left, right)| {
                let ordering = canonical_trace_step_order(left, right);
                (!ordering.is_eq()).then_some(ordering)
            })
            .unwrap_or(Ordering::Equal)
    })
}

fn canonical_trace_step_order(
    left: &InterpretedTraceStep,
    right: &InterpretedTraceStep,
) -> Ordering {
    left.caller_path
        .cmp(&right.caller_path)
        .then_with(|| left.kind.cmp(&right.kind))
        .then_with(|| left.target_path.cmp(&right.target_path))
        .then_with(|| {
            stable_source_range_order(left.source_range.as_ref(), right.source_range.as_ref())
        })
}

fn stable_source_range_order(
    left: Option<&SourceRangeIr>,
    right: Option<&SourceRangeIr>,
) -> Ordering {
    match (left, right) {
        // SourceFileId is an integrity identity and can incorporate an
        // artifact's absolute build location. It must not decide which
        // otherwise equivalent witness is rendered. Semantic paths above
        // distinguish the origin; byte offsets stabilize locations within it.
        (Some(left), Some(right)) => {
            (left.byte_start, left.byte_end).cmp(&(right.byte_start, right.byte_end))
        }
        // Prefer a trace with usable presentation evidence when the semantic
        // steps otherwise tie.
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

fn missing_requirements(
    requirements: &[ContractRequirementIr],
    satisfactions: &SatisfactionState,
) -> Option<Vec<ContractRequirementIr>> {
    if requirements.is_empty() {
        return (!satisfactions.unnamed).then(Vec::new);
    }
    let missing = requirements
        .iter()
        .filter(|requirement| {
            !satisfactions
                .named
                .contains(&normalize_requirement_name(&requirement.name))
        })
        .cloned()
        .collect::<Vec<_>>();
    (!missing.is_empty()).then_some(missing)
}

fn ambiguous_requirements(
    requirements: &[ContractRequirementIr],
) -> Vec<(String, Vec<ContractRequirementIr>)> {
    let mut groups = BTreeMap::<String, Vec<ContractRequirementIr>>::new();
    for requirement in requirements {
        groups
            .entry(normalize_requirement_name(&requirement.name))
            .or_default()
            .push(requirement.clone());
    }
    groups
        .into_iter()
        .filter(|(_, requirements)| requirements.len() > 1)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::{
        FunctionLookup, InMemoryArtifactLookup, IncompleteReason, InterpretationRoot,
        InterpretedFindingKind, InterpretedSafetyCallKind, InterpretedTraceStepKind,
        LayeredFunctionLookup, interpret, interpret_safety,
    };
    use crate::analysis::cache::{ArtifactAnalysisCache, ArtifactInfo, RustcArtifactId};
    use crate::analysis::facts::encoded::{ArtifactFactIr, FACT_IR_FORMAT_VERSION};
    use crate::analysis::facts::registry::SchemaRegistry;
    use crate::analysis::ir::{
        ArtifactAnalysisIr, CallEdgeIr, CallEdgeKindIr, CallId, CallSiteId, CallTargetIr,
        CallableAttributionIr, CallableKeyIr, ContractRequirementIr, EffectFactIr, EffectId,
        EffectKindIr, FunctionAttributesIr, FunctionBodyIr, FunctionBodyProvenanceIr,
        FunctionContractsIr, FunctionId, FunctionTargetIr, MacroExpansionFrameIr, MarkerId,
        MarkerIr, MarkerKindIr, MarkerProbingIr, MarkerSatisfactionIr, MarkerTargetIr,
        OpaqueTargetIr, RawContractIr, SafetyEffectGroupId, SourceFileId, SourceFileIr,
        SourceRangeIr,
    };
    use crate::config::{CallableEdgeAttribution, LintLevel, MarkerProbing, SniffTestConfig};
    use crate::contracts::ContractDocOverrides;
    use crate::namespace::{StableDefPathHash, StableInstanceHash};
    use crate::panics::CompilerAssertKind;
    use crate::path_patterns::PathPatterns;
    use crate::report_roots::ReportRootKind;
    use crate::safety::SafetyOpKind;

    struct CountingLookup<'a> {
        ir: &'a ArtifactAnalysisIr,
        function_calls: Cell<usize>,
    }

    impl FunctionLookup for CountingLookup<'_> {
        fn function(
            &self,
            function: FunctionId,
        ) -> Option<crate::analysis::graph::LoadedFunction<'_>> {
            self.function_calls.set(self.function_calls.get() + 1);
            FunctionLookup::function(self.ir, function)
        }

        fn function_in_scope(
            &self,
            scope: &crate::analysis::graph::BodyScope,
            function: FunctionId,
        ) -> Option<crate::analysis::graph::LoadedFunction<'_>> {
            FunctionLookup::function_in_scope(self.ir, scope, function)
        }
    }

    #[test]
    fn in_memory_artifact_lookup_manages_only_its_local_crate() {
        let analysis = ir(Vec::<FunctionBodyIr>::new());
        let lookup = InMemoryArtifactLookup::new(&analysis, 42);

        assert!(lookup.manages_stable_crate_id(42));
        assert!(!lookup.manages_stable_crate_id(7));
    }

    #[test]
    fn safety_only_interpretation_runs_one_domain_and_matches_the_full_oracle() {
        let root = id(1, 1);
        let analysis =
            ir(vec![body(root, "workspace::root").with_effect(
                unsafe_effect(0, SafetyOpKind::DerefRawPointer),
            )]);
        let roots = [report_root(root)];
        let config = SniffTestConfig::default();
        let full = interpret(&analysis, &roots, &config);
        let lookup = CountingLookup {
            ir: &analysis,
            function_calls: Cell::new(0),
        };

        let safety = interpret_safety(&lookup, &roots, &config);

        assert_eq!(lookup.function_calls.get(), 1);
        assert!(matches!(
            safety[0].findings.as_slice(),
            [finding]
                if matches!(
                    finding.kind,
                    InterpretedFindingKind::UnsafeOperation {
                        kind: SafetyOpKind::DerefRawPointer
                    }
                )
        ));
        assert_eq!(safety[0].root, full[0].root);
        assert_eq!(safety[0].findings, full[0].findings);
        assert_eq!(safety[0].completeness, full[0].completeness.safety);
    }

    #[test]
    fn macro_expanded_call_prefers_outer_invocation_and_keeps_ordered_trace_frames() {
        let root = id(1, 1);
        let sink = id(2, 1);
        let mut expanded_call = call(0, function_target(sink, "dependency::sink"));
        expanded_call.source_range = Some(source_range(10, 15));
        expanded_call.expanded_range = Some(source_range(50, 60));
        expanded_call.macro_expansions = vec![
            MacroExpansionFrameIr {
                macro_def: definition_hash(1, 10),
                display_path: String::from("workspace::outer"),
                source_range: Some(source_range(10, 15)),
            },
            MacroExpansionFrameIr {
                macro_def: definition_hash(1, 11),
                display_path: String::from("workspace::inner"),
                source_range: Some(source_range(30, 35)),
            },
        ];
        let analysis = ir_with_source(vec![body(root, "workspace::root").with_call(expanded_call)]);
        let config = SniffTestConfig::from_manifest_str(
            "[panics]\npanic-sink-namespaces = [\"dependency::sink\"]\n",
        )
        .expect("valid test configuration");

        let result = interpret(&analysis, &[report_root(root)], &config);
        let finding = &result[0].findings[0];

        assert_eq!(finding.source_range, Some(source_range(10, 15)));
        assert_eq!(finding.trace.steps.len(), 3);
        assert_eq!(
            finding
                .trace
                .steps
                .iter()
                .map(|step| (step.kind, step.caller_path.as_str()))
                .collect::<Vec<_>>(),
            [
                (
                    InterpretedTraceStepKind::Reachability(CallEdgeKindIr::MacroExpansion),
                    "workspace::root",
                ),
                (
                    InterpretedTraceStepKind::Reachability(CallEdgeKindIr::MacroExpansion),
                    "macro workspace::outer",
                ),
                (
                    InterpretedTraceStepKind::Reachability(CallEdgeKindIr::DirectCall),
                    "macro workspace::inner",
                ),
            ]
        );
        assert_eq!(
            finding.trace.steps[2].source_range,
            Some(source_range(50, 60))
        );
    }

    #[test]
    fn macro_expanded_unsafe_effect_keeps_macro_and_semantic_trace_steps() {
        let root = id(1, 1);
        let mut effect = unsafe_effect(0, SafetyOpKind::DerefRawPointer);
        effect.source_range = Some(source_range(10, 15));
        effect.expanded_range = Some(source_range(50, 60));
        effect.macro_expansions = vec![
            MacroExpansionFrameIr {
                macro_def: definition_hash(1, 10),
                display_path: String::from("workspace::outer"),
                source_range: Some(source_range(10, 15)),
            },
            MacroExpansionFrameIr {
                macro_def: definition_hash(1, 11),
                display_path: String::from("workspace::inner"),
                source_range: Some(source_range(30, 35)),
            },
        ];
        let analysis = ir_with_source(vec![body(root, "workspace::root").with_effect(effect)]);

        let result = interpret(&analysis, &[report_root(root)], &SniffTestConfig::default());
        let finding = &result[0].findings[0];

        assert_eq!(finding.source_range, Some(source_range(10, 15)));
        assert_eq!(
            finding
                .trace
                .steps
                .iter()
                .map(|step| step.kind)
                .collect::<Vec<_>>(),
            [
                InterpretedTraceStepKind::Reachability(CallEdgeKindIr::MacroExpansion),
                InterpretedTraceStepKind::Reachability(CallEdgeKindIr::MacroExpansion),
                InterpretedTraceStepKind::UnsafeOperation(SafetyOpKind::DerefRawPointer),
            ]
        );
        assert_eq!(
            finding.trace.steps[2].source_range,
            Some(source_range(50, 60))
        );
    }

    #[test]
    fn exact_instance_lookup_prefers_exact_ir_and_falls_back_to_generic_ir() {
        let generic = id(1, 1);
        let exact = FunctionId::exact(generic.def_path_hash, instance_hash(7));
        let only_generic =
            ir(vec![body(generic, "workspace::root").with_effect(
                assert_effect(0, CompilerAssertKind::BoundsCheck),
            )]);

        let fallback = interpret(
            &only_generic,
            &[report_root(exact)],
            &SniffTestConfig::default(),
        );
        assert!(fallback[0].findings.is_empty());
        assert!(fallback[0].completeness.panic.complete);

        let generic_and_exact = ir(vec![
            body(generic, "workspace::root")
                .with_effect(assert_effect(0, CompilerAssertKind::BoundsCheck)),
            body(exact, "workspace::root")
                .with_effect(assert_effect(0, CompilerAssertKind::Overflow)),
        ]);
        let preferred = interpret(
            &generic_and_exact,
            &[report_root(exact)],
            &SniffTestConfig::default(),
        );
        assert!(preferred[0].findings.is_empty());
        assert!(preferred[0].completeness.panic.complete);
    }

    #[test]
    fn consumer_overlay_wins_but_keeps_defining_unsafe_operation_facts() {
        let root = id(1, 1);
        let dependency_generic = id(2, 1);
        let dependency_exact =
            FunctionId::exact(dependency_generic.def_path_hash, instance_hash(7));
        let local = ir(vec![
            body(root, "workspace::root").with_call(call(
                0,
                function_target(dependency_exact, "dependency::generic::<workspace::Local>"),
            )),
            body(dependency_exact, "dependency::generic::<workspace::Local>")
                .consumer_instantiation(1),
        ]);
        let dependency = ir(vec![
            body(dependency_generic, "dependency::generic")
                .with_effect(unsafe_effect(0, SafetyOpKind::DerefRawPointer)),
        ]);
        let lookup = LayeredFunctionLookup::new(vec![&local, &dependency]);

        assert!(matches!(
            lookup
                .function(dependency_exact)
                .expect("exact overlay")
                .body()
                .provenance,
            FunctionBodyProvenanceIr::ConsumerInstantiation { .. }
        ));
        let result = interpret(&lookup, &[report_root(root)], &SniffTestConfig::default());
        let unsafe_findings = result[0]
            .findings
            .iter()
            .filter(|finding| {
                matches!(
                    finding.kind,
                    InterpretedFindingKind::UnsafeOperation {
                        kind: SafetyOpKind::DerefRawPointer
                    }
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(unsafe_findings.len(), 1);
        assert_eq!(unsafe_findings[0].function, dependency_generic);
        assert_eq!(unsafe_findings[0].trace.steps.len(), 2);
    }

    #[test]
    fn consumer_overlays_are_isolated_by_artifact_and_keep_exact_defining_facts() {
        let first_root = id(10, 1);
        let first_callback = id(10, 2);
        let second_root = id(20, 1);
        let second_callback = id(20, 2);
        let shared_definition = id(30, 1);
        let shared_exact = FunctionId::exact(shared_definition.def_path_hash, instance_hash(7));

        let first = cache(
            "first-consumer",
            10,
            vec![
                body(first_root, "first::root").with_call(call(
                    0,
                    function_target(shared_exact, "upstream::closure::<first::Callback>"),
                )),
                body(first_callback, "first::callback")
                    .with_effect(assert_effect(0, CompilerAssertKind::BoundsCheck)),
                body(shared_exact, "upstream::closure::<first::Callback>")
                    .consumer_instantiation(10)
                    .with_call(call(0, function_target(first_callback, "first::callback"))),
            ],
        );
        let second = cache(
            "second-consumer",
            20,
            vec![
                body(second_root, "second::root").with_call(call(
                    0,
                    function_target(shared_exact, "upstream::closure::<second::Callback>"),
                )),
                body(second_callback, "second::callback")
                    .with_effect(assert_effect(0, CompilerAssertKind::DivisionByZero)),
                body(shared_exact, "upstream::closure::<second::Callback>")
                    .consumer_instantiation(20)
                    .with_call(call(
                        0,
                        function_target(second_callback, "second::callback"),
                    )),
            ],
        );
        // Compiler-generated closure bodies can be exact definitions without
        // a generic body. Their source-level THIR safety facts must survive a
        // consumer overlay that has the same FunctionId.
        let upstream = cache(
            "upstream",
            30,
            vec![
                body(shared_exact, "upstream::closure")
                    .with_effect(unsafe_effect(0, SafetyOpKind::DerefRawPointer)),
            ],
        );
        let lookup = LayeredFunctionLookup::new(vec![&first, &second, &upstream]);

        let result = interpret(
            &lookup,
            &[report_root(first_root), report_root(second_root)],
            &SniffTestConfig::default(),
        );

        for root in &result {
            assert!(root.completeness.panic.complete);
            assert!(root.findings.iter().any(|finding| matches!(
                finding.kind,
                InterpretedFindingKind::UnsafeOperation {
                    kind: SafetyOpKind::DerefRawPointer
                }
            )));
        }
    }

    #[test]
    fn callable_target_resolution_across_evidence_artifacts_stays_complete() {
        let root = id(10, 1);
        let evidence_holder = id(20, 1);
        let target_generic = id(30, 1);
        let target_exact = FunctionId::exact(target_generic.def_path_hash, instance_hash(7));
        let key = CallableKeyIr::DynDispatch(definition_hash(99, 1));

        let mut invocation = call(
            1,
            CallTargetIr::OpaqueBoundary {
                description: String::from("dynamic invocation"),
                target: None,
            },
        );
        invocation.kind = CallEdgeKindIr::IndirectCall;
        invocation.callable_keys = vec![key];
        let invoking_consumer = cache(
            "invoking-consumer",
            10,
            vec![
                body(root, "invoking_consumer::root")
                    .with_call(call(
                        0,
                        function_target(evidence_holder, "evidence_consumer::expose"),
                    ))
                    .with_call(invocation),
            ],
        );

        let mut evidence = call(
            0,
            function_target(target_exact, "upstream::target::<evidence_consumer::Local>"),
        );
        evidence.kind = CallEdgeKindIr::VTableEntry;
        evidence.applicable_attribution = vec![CallableAttributionIr::ErasureSites];
        evidence.callable_keys = vec![key];
        let evidence_consumer = cache(
            "evidence-consumer",
            20,
            vec![
                body(evidence_holder, "evidence_consumer::expose").with_call(evidence),
                body(target_exact, "upstream::target::<evidence_consumer::Local>")
                    .consumer_instantiation(20)
                    .with_effect(assert_effect(0, CompilerAssertKind::Overflow)),
            ],
        );
        let defining_artifact = cache(
            "upstream",
            30,
            vec![body(target_generic, "upstream::target")],
        );
        let lookup = LayeredFunctionLookup::new(vec![
            &invoking_consumer,
            &evidence_consumer,
            &defining_artifact,
        ]);
        let mut config = SniffTestConfig::default();
        config.analysis.callable_edge_attribution = CallableEdgeAttribution::CallSites;

        let result = interpret(&lookup, &[report_root(root)], &config);

        assert!(result[0].completeness.panic.complete);
        assert!(result[0].completeness.safety.complete);
    }

    #[test]
    fn resolved_callable_reuses_the_raw_invocation_safety_group() {
        let root = id(1, 1);
        let dependency_generic = id(2, 1);
        let dependency_exact =
            FunctionId::exact(dependency_generic.def_path_hash, instance_hash(7));
        let target = id(1, 2);
        let key = CallableKeyIr::DynDispatch(definition_hash(99, 1));

        let mut overlay_invocation = call(
            0,
            CallTargetIr::OpaqueBoundary {
                description: String::from("dynamic invocation"),
                target: None,
            },
        );
        overlay_invocation.kind = CallEdgeKindIr::IndirectCall;
        overlay_invocation.requires_unsafe = true;
        overlay_invocation.source_range = Some(source_range(20, 25));
        overlay_invocation.expanded_range = Some(source_range(20, 25));
        overlay_invocation.callee_range = Some(source_range(20, 21));
        overlay_invocation.safety_effect_group = Some(SafetyEffectGroupId::new(10));
        overlay_invocation.callable_keys = vec![key];

        let mut evidence = call(1, unsafe_function_target(target, "workspace::target"));
        evidence.kind = CallEdgeKindIr::VTableEntry;
        evidence.applicable_attribution = vec![CallableAttributionIr::ErasureSites];
        evidence.callable_keys = vec![key];

        let mut marker = justification_marker(
            0,
            MarkerKindIr::SafetyJustification,
            MarkerTargetIr::Call(CallId::new(0)),
            None,
        );
        marker.identity = String::from("definition-unsafe-scope");

        let local = ir_with_source(vec![
            body(root, "workspace::root").with_call(call(
                0,
                function_target(dependency_exact, "dependency::generic::<workspace::Local>"),
            )),
            body(dependency_exact, "dependency::generic::<workspace::Local>")
                .consumer_instantiation(1)
                .with_call(overlay_invocation)
                .with_call(evidence)
                .with_marker(marker),
            body(target, "workspace::target").unsafe_function(),
        ]);

        let mut defining_invocation = call(
            0,
            CallTargetIr::OpaqueBoundary {
                description: String::from("dynamic invocation"),
                target: None,
            },
        );
        defining_invocation.kind = CallEdgeKindIr::IndirectCall;
        defining_invocation.requires_unsafe = true;
        defining_invocation.source_range = Some(source_range(20, 25));
        defining_invocation.expanded_range = Some(source_range(20, 25));
        defining_invocation.callee_range = Some(source_range(20, 21));
        defining_invocation.safety_effect_group = Some(SafetyEffectGroupId::new(7));
        defining_invocation.callable_keys = vec![key];
        let dependency = ir_with_source(vec![
            body(dependency_generic, "dependency::generic").with_call(defining_invocation),
        ]);
        let lookup = LayeredFunctionLookup::new(vec![&local, &dependency]);
        let mut config = SniffTestConfig::default();
        config.analysis.callable_edge_attribution = CallableEdgeAttribution::CallSites;

        let result = interpret(&lookup, &[report_root(root)], &config);

        assert!(
            !result[0].findings.iter().any(|finding| matches!(
                finding.kind,
                InterpretedFindingKind::AmbiguousSafetyMarker { .. }
            )),
            "the raw and resolved alternatives at one invocation share one definition-site group"
        );
    }

    #[test]
    fn consumer_overlay_calls_reuse_the_defining_unsafe_scope_group() {
        let root = id(1, 1);
        let dependency_generic = id(2, 1);
        let dependency_exact =
            FunctionId::exact(dependency_generic.def_path_hash, instance_hash(7));
        let first_generic = id(2, 2);
        let first_exact = FunctionId::exact(first_generic.def_path_hash, instance_hash(8));
        let second_generic = id(2, 3);
        let second_exact = FunctionId::exact(second_generic.def_path_hash, instance_hash(9));

        let mut overlay_first = call(
            0,
            unsafe_function_target(first_exact, "dependency::first::<workspace::Local>"),
        );
        overlay_first.requires_unsafe = true;
        overlay_first.source_range = Some(source_range(20, 25));
        overlay_first.expanded_range = Some(source_range(20, 25));
        overlay_first.callee_range = Some(source_range(20, 21));
        overlay_first.safety_effect_group = Some(SafetyEffectGroupId::new(10));
        let mut overlay_second = call(
            1,
            unsafe_function_target(second_exact, "dependency::second::<workspace::Local>"),
        );
        overlay_second.requires_unsafe = true;
        overlay_second.source_range = Some(source_range(30, 35));
        overlay_second.expanded_range = Some(source_range(30, 35));
        overlay_second.callee_range = Some(source_range(30, 31));
        overlay_second.safety_effect_group = Some(SafetyEffectGroupId::new(11));
        let mut first_marker = justification_marker(
            0,
            MarkerKindIr::SafetyJustification,
            MarkerTargetIr::Call(CallId::new(0)),
            None,
        );
        first_marker.identity = String::from("definition-unsafe-scope");
        let mut second_marker = justification_marker(
            1,
            MarkerKindIr::SafetyJustification,
            MarkerTargetIr::Call(CallId::new(1)),
            None,
        );
        second_marker.identity = String::from("definition-unsafe-scope");

        let local = ir_with_source(vec![
            body(root, "workspace::root").with_call(call(
                0,
                function_target(dependency_exact, "dependency::generic::<workspace::Local>"),
            )),
            body(dependency_exact, "dependency::generic::<workspace::Local>")
                .consumer_instantiation(1)
                .with_call(overlay_first)
                .with_call(overlay_second)
                .with_marker(first_marker)
                .with_marker(second_marker),
        ]);

        let mut defining_first = call(
            0,
            unsafe_function_target(first_generic, "dependency::first"),
        );
        defining_first.requires_unsafe = true;
        defining_first.source_range = Some(source_range(20, 25));
        defining_first.expanded_range = Some(source_range(20, 25));
        defining_first.callee_range = Some(source_range(20, 21));
        defining_first.safety_effect_group = Some(SafetyEffectGroupId::new(7));
        let mut defining_second = call(
            1,
            unsafe_function_target(second_generic, "dependency::second"),
        );
        defining_second.requires_unsafe = true;
        defining_second.source_range = Some(source_range(30, 35));
        defining_second.expanded_range = Some(source_range(30, 35));
        defining_second.callee_range = Some(source_range(30, 31));
        defining_second.safety_effect_group = Some(SafetyEffectGroupId::new(7));
        let dependency = ir_with_source(vec![
            body(dependency_generic, "dependency::generic")
                .with_call(defining_first)
                .with_call(defining_second),
            body(first_generic, "dependency::first").unsafe_function(),
            body(second_generic, "dependency::second").unsafe_function(),
        ]);
        let lookup = LayeredFunctionLookup::new(vec![&local, &dependency]);

        let result = interpret(&lookup, &[report_root(root)], &SniffTestConfig::default());

        assert!(!result[0].findings.iter().any(|finding| matches!(
            finding.kind,
            InterpretedFindingKind::AmbiguousSafetyMarker { .. }
        )));
    }

    #[test]
    fn consumer_overlay_calls_reuse_defining_builtin_unsafe_context() {
        let root = id(1, 1);
        let dependency_generic = id(2, 1);
        let dependency_exact =
            FunctionId::exact(dependency_generic.def_path_hash, instance_hash(7));
        let callee_generic = id(2, 2);
        let callee_exact = FunctionId::exact(callee_generic.def_path_hash, instance_hash(8));

        let mut overlay_call = call(
            0,
            unsafe_function_target(callee_exact, "dependency::callee::<workspace::Local>"),
        );
        overlay_call.requires_unsafe = true;
        overlay_call.source_range = Some(source_range(20, 25));
        overlay_call.expanded_range = Some(source_range(20, 25));
        overlay_call.callee_range = Some(source_range(20, 21));

        let local = ir_with_source(vec![
            body(root, "workspace::root").with_call(call(
                0,
                function_target(dependency_exact, "dependency::generic::<workspace::Local>"),
            )),
            body(dependency_exact, "dependency::generic::<workspace::Local>")
                .consumer_instantiation(1)
                .with_call(overlay_call),
            body(callee_exact, "dependency::callee::<workspace::Local>").unsafe_function(),
        ]);

        let mut defining_call = call(
            0,
            unsafe_function_target(callee_generic, "dependency::callee"),
        );
        defining_call.requires_unsafe = true;
        defining_call.inside_builtin_unsafe = true;
        defining_call.source_range = Some(source_range(20, 25));
        defining_call.expanded_range = Some(source_range(20, 25));
        defining_call.callee_range = Some(source_range(20, 21));
        let dependency = ir_with_source(vec![
            body(dependency_generic, "dependency::generic").with_call(defining_call),
            body(callee_generic, "dependency::callee").unsafe_function(),
        ]);
        let lookup = LayeredFunctionLookup::new(vec![&local, &dependency]);

        let result = interpret(&lookup, &[report_root(root)], &SniffTestConfig::default());

        assert!(
            !result[0]
                .findings
                .iter()
                .any(|finding| matches!(finding.kind, InterpretedFindingKind::SafetyCall { .. }))
        );
    }

    #[test]
    fn consumer_overlay_concrete_trait_call_reuses_defining_safety_marker() {
        let root = id(1, 1);
        let dependency_generic = id(2, 1);
        let dependency_exact =
            FunctionId::exact(dependency_generic.def_path_hash, instance_hash(7));
        let trait_method = id(2, 2);
        let dependency_impl = id(2, 3);
        let concrete_impl = id(1, 2);

        let mut overlay_call = call(
            0,
            unsafe_function_target(concrete_impl, "workspace::Local::apply"),
        );
        overlay_call.requires_unsafe = true;
        overlay_call.source_range = Some(source_range(20, 30));
        overlay_call.expanded_range = Some(source_range(20, 30));
        overlay_call.callee_range = Some(source_range(20, 25));
        overlay_call.safety_effect_group = Some(SafetyEffectGroupId::new(10));
        let local = ir_with_source(vec![
            body(root, "workspace::root").with_call(call(
                0,
                function_target(dependency_exact, "dependency::invoke::<workspace::Local>"),
            )),
            body(dependency_exact, "dependency::invoke::<workspace::Local>")
                .consumer_instantiation(1)
                .with_call(overlay_call),
            body(concrete_impl, "workspace::Local::apply").unsafe_function(),
        ]);

        let CallTargetIr::Function(mut trait_metadata) =
            unsafe_function_target(trait_method, "dependency::Action::apply")
        else {
            unreachable!("unsafe_function_target always creates a function target");
        };
        trait_metadata.contracts.safety = Some(contract(vec![requirement(
            "invariant",
            "implementations uphold the private invariant",
        )]));
        let mut defining_call = call(
            0,
            unsafe_function_target(dependency_impl, "dependency::DependencyAction::apply"),
        );
        defining_call.source_target = Some(trait_metadata);
        defining_call.requires_unsafe = true;
        defining_call.source_range = Some(source_range(20, 30));
        defining_call.expanded_range = Some(source_range(20, 30));
        defining_call.callee_range = Some(source_range(20, 25));
        defining_call.safety_effect_group = Some(SafetyEffectGroupId::new(7));
        let marker = justification_marker(
            0,
            MarkerKindIr::SafetyJustification,
            MarkerTargetIr::Call(CallId::new(0)),
            Some("invariant"),
        );
        let dependency = ir_with_source(vec![
            body(dependency_generic, "dependency::invoke")
                .with_call(defining_call)
                .with_marker(marker),
        ]);
        let lookup = LayeredFunctionLookup::new(vec![&local, &dependency]);

        let result = interpret(&lookup, &[report_root(root)], &SniffTestConfig::default());

        assert!(
            !result[0]
                .findings
                .iter()
                .any(|finding| matches!(finding.kind, InterpretedFindingKind::SafetyCall { .. }))
        );
    }

    #[test]
    fn consumer_overlay_concrete_trait_call_reuses_defining_panic_contract_and_marker() {
        let root = id(1, 1);
        let dependency_generic = id(2, 1);
        let dependency_exact =
            FunctionId::exact(dependency_generic.def_path_hash, instance_hash(7));
        let trait_method = id(2, 2);
        let dependency_impl = id(2, 3);
        let concrete_impl = id(1, 2);

        let mut overlay_call = call(
            0,
            function_target(concrete_impl, "workspace::Local::may_panic"),
        );
        overlay_call.expanded_range = Some(source_range(20, 30));
        overlay_call.callee_range = Some(source_range(20, 25));
        let local = ir_with_source(vec![
            body(root, "workspace::root").with_call(call(
                0,
                function_target(dependency_exact, "dependency::invoke::<workspace::Local>"),
            )),
            body(dependency_exact, "dependency::invoke::<workspace::Local>")
                .consumer_instantiation(1)
                .with_call(overlay_call),
            body(concrete_impl, "workspace::Local::may_panic")
                .with_effect(assert_effect(0, CompilerAssertKind::BoundsCheck)),
        ]);

        let CallTargetIr::Function(mut trait_metadata) =
            function_target(trait_method, "dependency::Action::may_panic")
        else {
            unreachable!("function_target always creates a function target");
        };
        trait_metadata.contracts.panic = Some(contract(vec![requirement(
            "invariant",
            "the private invariant holds",
        )]));
        let mut defining_call = call(
            0,
            function_target_with_contracts(
                dependency_impl,
                "dependency::DependencyAction::may_panic",
                FunctionContractsIr {
                    panic: Some(contract(vec![requirement(
                        "dependency",
                        "the dependency-local implementation precondition holds",
                    )])),
                    safety: None,
                },
            ),
        );
        defining_call.source_target = Some(trait_metadata);
        defining_call.expanded_range = Some(source_range(20, 30));
        defining_call.callee_range = Some(source_range(20, 25));
        let marker = justification_marker(
            0,
            MarkerKindIr::PanicJustification,
            MarkerTargetIr::Call(CallId::new(0)),
            Some("invariant"),
        );
        let dependency = ir_with_source(vec![
            body(dependency_generic, "dependency::invoke")
                .with_call(defining_call)
                .with_marker(marker),
        ]);
        let lookup = LayeredFunctionLookup::new(vec![&local, &dependency]);

        let result = interpret(&lookup, &[report_root(root)], &SniffTestConfig::default());

        assert!(result[0].findings.is_empty());
    }

    #[test]
    fn source_trait_without_docs_falls_back_to_the_concrete_impl_contract() {
        let root = id(1, 1);
        let dependency_generic = id(2, 1);
        let dependency_exact =
            FunctionId::exact(dependency_generic.def_path_hash, instance_hash(7));
        let trait_method = id(2, 2);
        let dependency_impl = id(2, 3);
        let concrete_impl = id(1, 2);

        let mut overlay_call = call(
            0,
            function_target_with_contracts(
                concrete_impl,
                "workspace::Local::may_panic",
                FunctionContractsIr {
                    panic: Some(contract(vec![requirement(
                        "concrete",
                        "the concrete implementation precondition holds",
                    )])),
                    safety: None,
                },
            ),
        );
        overlay_call.expanded_range = Some(source_range(20, 30));
        overlay_call.callee_range = Some(source_range(20, 25));
        let local = ir_with_source(vec![
            body(root, "workspace::root").with_call(call(
                0,
                function_target(dependency_exact, "dependency::invoke::<workspace::Local>"),
            )),
            body(dependency_exact, "dependency::invoke::<workspace::Local>")
                .consumer_instantiation(1)
                .with_call(overlay_call),
            body(concrete_impl, "workspace::Local::may_panic")
                .with_effect(assert_effect(0, CompilerAssertKind::BoundsCheck)),
        ]);

        let CallTargetIr::Function(trait_metadata) =
            function_target(trait_method, "dependency::Action::may_panic")
        else {
            unreachable!("function_target always creates a function target");
        };
        let mut defining_call = call(
            0,
            function_target_with_contracts(
                dependency_impl,
                "dependency::DependencyAction::may_panic",
                FunctionContractsIr {
                    panic: Some(contract(vec![requirement(
                        "dependency",
                        "the dependency-local implementation precondition holds",
                    )])),
                    safety: None,
                },
            ),
        );
        defining_call.source_target = Some(trait_metadata);
        defining_call.expanded_range = Some(source_range(20, 30));
        defining_call.callee_range = Some(source_range(20, 25));
        let dependency = ir_with_source(vec![
            body(dependency_generic, "dependency::invoke").with_call(defining_call),
        ]);
        let lookup = LayeredFunctionLookup::new(vec![&local, &dependency]);

        let result = interpret(&lookup, &[report_root(root)], &SniffTestConfig::default());
        let finding = result[0]
            .findings
            .iter()
            .find(|finding| matches!(finding.kind, InterpretedFindingKind::DocumentedPanic { .. }))
            .expect("the concrete implementation contract remains active");

        assert_eq!(finding.missing_requirements[0].name, "concrete");
    }

    #[test]
    fn ambiguous_source_markers_leave_consumer_overlay_obligations_unsatisfied() {
        let root = id(1, 1);
        let dependency_generic = id(2, 1);
        let dependency_exact =
            FunctionId::exact(dependency_generic.def_path_hash, instance_hash(7));
        let first_trait_method = id(2, 2);
        let second_trait_method = id(2, 3);
        let concrete_impl = id(1, 2);

        let mut overlay_call = call(
            0,
            unsafe_function_target(concrete_impl, "workspace::Local::apply"),
        );
        overlay_call.requires_unsafe = true;
        overlay_call.expanded_range = Some(source_range(20, 30));
        overlay_call.callee_range = Some(source_range(20, 25));
        let local = ir_with_source(vec![
            body(root, "workspace::root").with_call(call(
                0,
                function_target(dependency_exact, "dependency::invoke::<workspace::Local>"),
            )),
            body(dependency_exact, "dependency::invoke::<workspace::Local>")
                .consumer_instantiation(1)
                .with_call(overlay_call),
            body(concrete_impl, "workspace::Local::apply").unsafe_function(),
        ]);

        let defining_call = |id, method, path, group| {
            let CallTargetIr::Function(trait_metadata) = unsafe_function_target(method, path)
            else {
                unreachable!("unsafe_function_target always creates a function target");
            };
            let mut call = call(
                id,
                CallTargetIr::OpaqueBoundary {
                    description: String::from("generic unsafe trait call"),
                    target: Some(OpaqueTargetIr::Trait(trait_metadata)),
                },
            );
            call.kind = CallEdgeKindIr::IndirectCall;
            call.requires_unsafe = true;
            call.expanded_range = Some(source_range(20, 30));
            call.callee_range = Some(source_range(20, 25));
            call.safety_effect_group = Some(SafetyEffectGroupId::new(group));
            call
        };
        let marker = justification_marker(
            0,
            MarkerKindIr::SafetyJustification,
            MarkerTargetIr::Call(CallId::new(0)),
            None,
        );
        let dependency = ir_with_source(vec![
            body(dependency_generic, "dependency::invoke")
                .with_call(defining_call(
                    0,
                    first_trait_method,
                    "dependency::First::apply",
                    7,
                ))
                .with_call(defining_call(
                    1,
                    second_trait_method,
                    "dependency::Second::apply",
                    8,
                ))
                .with_marker(marker),
        ]);
        let lookup = LayeredFunctionLookup::new(vec![&local, &dependency]);

        let result = interpret(&lookup, &[report_root(root)], &SniffTestConfig::default());

        assert!(
            result[0]
                .findings
                .iter()
                .any(|finding| matches!(finding.kind, InterpretedFindingKind::SafetyCall { .. }))
        );
    }

    #[test]
    fn unmanaged_consumer_overlay_hides_internal_safety_but_follows_managed_target() {
        let root = id(1, 1);
        let callback = id(1, 2);
        let overlay_generic = id(9, 1);
        let overlay_exact = FunctionId::exact(overlay_generic.def_path_hash, instance_hash(7));
        let inner = id(9, 2);
        let mut root_call = call(
            0,
            unsafe_function_target(overlay_exact, "unmanaged::overlay::<workspace::Local>"),
        );
        root_call.requires_unsafe = true;
        let mut inner_call = call(0, unsafe_function_target(inner, "unmanaged::inner"));
        inner_call.requires_unsafe = true;
        let callback_call = call(
            1,
            function_target(callback, "workspace::callback::<workspace::Local>"),
        );
        let local = ir(vec![
            body(root, "workspace::root").with_call(root_call),
            body(callback, "workspace::callback")
                .with_effect(unsafe_effect(0, SafetyOpKind::DerefRawPointer)),
            body(overlay_exact, "unmanaged::overlay::<workspace::Local>")
                .consumer_instantiation(1)
                .with_call(inner_call)
                .with_call(callback_call),
        ]);
        let lookup = ManagedLookup {
            ir: &local,
            stable_crate_ids: vec![root.def_path_hash.stable_crate_id()],
        };

        let result = interpret(&lookup, &[report_root(root)], &SniffTestConfig::default());
        let unsafe_calls = result[0]
            .findings
            .iter()
            .filter(|finding| {
                matches!(
                    finding.kind,
                    InterpretedFindingKind::SafetyCall {
                        kind: InterpretedSafetyCallKind::Unsafe,
                        ..
                    }
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(unsafe_calls.len(), 1);
        assert_eq!(unsafe_calls[0].function, root);
        assert!(result[0].findings.iter().any(|finding| {
            finding.function == callback
                && matches!(
                    finding.kind,
                    InterpretedFindingKind::UnsafeOperation {
                        kind: SafetyOpKind::DerefRawPointer
                    }
                )
        }));
        assert!(
            !result[0]
                .findings
                .iter()
                .any(|finding| finding.function == overlay_exact)
        );
        assert!(result[0].completeness.safety.complete);
    }

    #[test]
    fn unmanaged_consumer_overlays_relay_safety_to_a_managed_target() {
        let root = id(1, 1);
        let callback = id(1, 2);
        let first_generic = id(9, 1);
        let first_overlay = FunctionId::exact(first_generic.def_path_hash, instance_hash(7));
        let second_generic = id(9, 2);
        let second_overlay = FunctionId::exact(second_generic.def_path_hash, instance_hash(8));
        let local = ir(vec![
            body(root, "workspace::root").with_call(call(
                0,
                function_target(first_overlay, "unmanaged::first::<workspace::Local>"),
            )),
            body(first_overlay, "unmanaged::first::<workspace::Local>")
                .consumer_instantiation(1)
                .with_call(call(
                    0,
                    function_target(second_overlay, "unmanaged::second::<workspace::Local>"),
                )),
            body(second_overlay, "unmanaged::second::<workspace::Local>")
                .consumer_instantiation(1)
                .with_call(call(
                    0,
                    function_target(callback, "workspace::callback::<workspace::Local>"),
                )),
            body(callback, "workspace::callback")
                .with_effect(unsafe_effect(0, SafetyOpKind::DerefRawPointer)),
        ]);
        let lookup = ManagedLookup {
            ir: &local,
            stable_crate_ids: vec![root.def_path_hash.stable_crate_id()],
        };

        let result = interpret(&lookup, &[report_root(root)], &SniffTestConfig::default());
        let root = &result[0];

        assert!(root.findings.iter().any(|finding| {
            finding.function == callback
                && matches!(
                    finding.kind,
                    InterpretedFindingKind::UnsafeOperation {
                        kind: SafetyOpKind::DerefRawPointer
                    }
                )
        }));
        assert!(root.completeness.safety.complete);
    }

    #[test]
    fn managed_consumer_overlay_without_defining_body_is_incomplete_but_relays_safety() {
        let root = id(1, 1);
        let callback = id(1, 2);
        let definition = id(2, 1);
        let overlay = FunctionId::exact(definition.def_path_hash, instance_hash(7));
        let local_ir = ir(vec![
            body(root, "workspace::root").with_call(call(
                0,
                function_target(overlay, "dependency::generic::<workspace::Local>"),
            )),
            body(overlay, "dependency::generic::<workspace::Local>")
                .consumer_instantiation(1)
                .with_call(call(0, function_target(callback, "workspace::callback"))),
            body(callback, "workspace::callback")
                .with_effect(unsafe_effect(0, SafetyOpKind::DerefRawPointer)),
        ]);
        let dependency_ir = ir(Vec::<FunctionBodyIr>::new());
        let local = ManagedLookup {
            ir: &local_ir,
            stable_crate_ids: vec![root.def_path_hash.stable_crate_id()],
        };
        let dependency = ManagedLookup {
            ir: &dependency_ir,
            stable_crate_ids: vec![definition.def_path_hash.stable_crate_id()],
        };
        let lookup = LayeredFunctionLookup::new(vec![&local, &dependency]);

        let result = interpret(&lookup, &[report_root(root)], &SniffTestConfig::default());
        let root = &result[0];

        assert!(!root.completeness.safety.complete);
        assert!(matches!(
            root.completeness.safety.reasons.as_slice(),
            [IncompleteReason::MissingBody { function, .. }] if *function == overlay
        ));
        assert!(root.findings.iter().any(|finding| {
            finding.function == callback
                && matches!(
                    finding.kind,
                    InterpretedFindingKind::UnsafeOperation {
                        kind: SafetyOpKind::DerefRawPointer
                    }
                )
        }));
    }

    #[test]
    fn managed_consumer_overlay_uses_a_different_exact_defining_source_body() {
        let root = id(1, 1);
        let definition = id(2, 1);
        let overlay = FunctionId::exact(definition.def_path_hash, instance_hash(7));
        let defining_source = FunctionId::exact(definition.def_path_hash, instance_hash(8));
        let local_ir = ir(vec![
            body(root, "workspace::root").with_call(call(
                0,
                function_target(overlay, "dependency::nested::<workspace::Local>"),
            )),
            body(overlay, "dependency::nested::<workspace::Local>").consumer_instantiation(1),
        ]);
        let dependency_ir = ir(vec![
            body(defining_source, "dependency::nested")
                .with_effect(unsafe_effect(0, SafetyOpKind::DerefRawPointer)),
        ]);
        let local = ManagedLookup {
            ir: &local_ir,
            stable_crate_ids: vec![root.def_path_hash.stable_crate_id()],
        };
        let dependency = ManagedLookup {
            ir: &dependency_ir,
            stable_crate_ids: vec![definition.def_path_hash.stable_crate_id()],
        };
        let lookup = LayeredFunctionLookup::new(vec![&local, &dependency]);

        let result = interpret(&lookup, &[report_root(root)], &SniffTestConfig::default());
        let root = &result[0];

        assert!(root.completeness.safety.complete);
        assert!(root.findings.iter().any(|finding| {
            finding.function == defining_source
                && matches!(
                    finding.kind,
                    InterpretedFindingKind::UnsafeOperation {
                        kind: SafetyOpKind::DerefRawPointer
                    }
                )
        }));
    }

    #[test]
    fn unmanaged_consumer_overlay_reports_a_managed_missing_target() {
        let root = id(1, 1);
        let unmanaged_definition = id(9, 1);
        let overlay = FunctionId::exact(unmanaged_definition.def_path_hash, instance_hash(7));
        let missing_target = id(2, 1);
        let local_ir = ir(vec![
            body(root, "workspace::root").with_call(call(
                0,
                function_target(overlay, "unmanaged::generic::<workspace::Local>"),
            )),
            body(overlay, "unmanaged::generic::<workspace::Local>")
                .consumer_instantiation(1)
                .with_call(call(
                    0,
                    function_target(missing_target, "dependency::missing"),
                )),
        ]);
        let dependency_ir = ir(Vec::<FunctionBodyIr>::new());
        let local = ManagedLookup {
            ir: &local_ir,
            stable_crate_ids: vec![root.def_path_hash.stable_crate_id()],
        };
        let dependency = ManagedLookup {
            ir: &dependency_ir,
            stable_crate_ids: vec![missing_target.def_path_hash.stable_crate_id()],
        };
        let lookup = LayeredFunctionLookup::new(vec![&local, &dependency]);

        let result = interpret(&lookup, &[report_root(root)], &SniffTestConfig::default());
        let safety = &result[0].completeness.safety;

        assert!(!safety.complete);
        assert!(matches!(
            safety.reasons.as_slice(),
            [IncompleteReason::MissingBody { function, .. }] if *function == missing_target
        ));
    }

    #[test]
    fn foreign_function_declarations_are_intentional_body_boundaries() {
        let root = id(1, 1);
        let foreign = id(1, 2);
        let mut target = function_target(foreign, "workspace::foreign_function");
        let CallTargetIr::Function(metadata) = &mut target else {
            unreachable!("function_target always constructs a function target");
        };
        metadata.attributes.has_rust_body = false;
        metadata.attributes.is_foreign = true;
        let analysis = ir(vec![
            body(root, "workspace::root").with_call(call(0, target)),
        ]);

        let result = interpret(&analysis, &[report_root(root)], &SniffTestConfig::default());
        let root = &result[0];

        assert!(root.findings.is_empty());
        assert!(root.completeness.panic.complete);
        assert!(root.completeness.safety.complete);
    }

    #[test]
    fn bodyless_trait_method_is_a_complete_opaque_panic_boundary() {
        let root = id(1, 1);
        let required_method = id(1, 2);
        let mut target = function_target(required_method, "workspace::Trait::required");
        let CallTargetIr::Function(metadata) = &mut target else {
            unreachable!("function_target always constructs a function target");
        };
        metadata.attributes.has_rust_body = false;
        let analysis = ir(vec![
            body(root, "workspace::root").with_call(call(0, target)),
        ]);

        let result = interpret(&analysis, &[report_root(root)], &SniffTestConfig::default());
        let root = &result[0];

        assert!(root.findings.iter().any(|finding| matches!(
            finding.kind,
            InterpretedFindingKind::OpaquePanicBoundary { .. }
        )));
        assert!(root.completeness.panic.complete);
        assert!(root.completeness.safety.complete);
    }

    #[test]
    fn missing_body_reasons_preserve_source_ranges() {
        let root = id(1, 1);
        let missing = id(2, 1);
        let call_range = source_range(10, 20);
        let mut edge = call(0, function_target(missing, "dependency::missing"));
        edge.source_range = Some(call_range.clone());
        let mut effect = assert_effect(0, CompilerAssertKind::BoundsCheck);
        effect.source_range = Some(source_range(30, 40));
        let analysis = ArtifactAnalysisIr::new(
            vec![
                body(root, "workspace::root")
                    .with_call(edge)
                    .with_effect(effect)
                    .into(),
            ],
            vec![source_file()],
        )
        .expect("valid test IR");

        let result = interpret(&analysis, &[report_root(root)], &SniffTestConfig::default());
        let root = &result[0];

        assert!(root.findings.is_empty());
        for completeness in [&root.completeness.panic, &root.completeness.safety] {
            assert!(!completeness.complete);
            let IncompleteReason::MissingBody {
                source_range,
                trace,
                ..
            } = &completeness.reasons[0]
            else {
                panic!("expected a missing-body reason");
            };
            assert_eq!(source_range.as_ref(), Some(&call_range));
            assert_eq!(trace.steps[0].source_range.as_ref(), Some(&call_range));
        }
    }

    #[test]
    fn unmanaged_compiler_crate_boundary_keeps_analysis_complete() {
        let root = id(1, 1);
        let compiler_helper = id(99, 1);
        let analysis = ir(vec![body(root, "workspace::root").with_call(call(
            0,
            function_target(compiler_helper, "core::fmt::Arguments::from_str"),
        ))]);
        let lookup = ManagedLookup {
            ir: &analysis,
            stable_crate_ids: vec![root.def_path_hash.stable_crate_id()],
        };

        let result = interpret(&lookup, &[report_root(root)], &SniffTestConfig::default());
        let root = &result[0];

        assert!(root.findings.is_empty());
        assert!(root.completeness.panic.complete);
        assert!(root.completeness.safety.complete);
    }

    #[test]
    fn managed_dependency_with_an_omitted_body_remains_incomplete() {
        let root = id(1, 1);
        let missing_dependency_body = id(2, 1);
        let local_ir = ir(vec![body(root, "workspace::root").with_call(call(
            0,
            function_target(missing_dependency_body, "dependency::missing"),
        ))]);
        let dependency_ir = ir(Vec::<FunctionBodyIr>::new());
        let local = ManagedLookup {
            ir: &local_ir,
            stable_crate_ids: vec![root.def_path_hash.stable_crate_id()],
        };
        let dependency = ManagedLookup {
            ir: &dependency_ir,
            stable_crate_ids: vec![missing_dependency_body.def_path_hash.stable_crate_id()],
        };
        let lookup = LayeredFunctionLookup::new(vec![&local, &dependency]);

        let result = interpret(&lookup, &[report_root(root)], &SniffTestConfig::default());
        let root = &result[0];

        for completeness in [&root.completeness.panic, &root.completeness.safety] {
            assert!(!completeness.complete);
            assert!(matches!(
                completeness.reasons.as_slice(),
                [IncompleteReason::MissingBody { function, .. }]
                    if *function == missing_dependency_body
            ));
        }
    }

    #[test]
    fn policy_interpretation_is_independent_of_lint_levels() {
        let root = id(1, 1);
        let analysis =
            ir(vec![body(root, "workspace::root").with_effect(
                assert_effect(0, CompilerAssertKind::Overflow),
            )]);
        let mut allowed = SniffTestConfig::default();
        allowed.panics.lints.compiler_assert = LintLevel::Allow;
        let mut denied = allowed.clone();
        denied.panics.lints.compiler_assert = LintLevel::Deny;

        assert_eq!(
            interpret(&analysis, &[report_root(root)], &allowed),
            interpret(&analysis, &[report_root(root)], &denied)
        );
    }

    #[test]
    fn named_requirements_use_only_markers_applicable_to_the_selected_probe_mode() {
        let root = id(1, 1);
        let target = id(2, 1);
        let requirement = requirement("Valid Input", "the index is in range");
        let edge = call(
            0,
            function_target_with_contracts(
                target,
                "dependency::checked",
                FunctionContractsIr {
                    panic: Some(contract(vec![requirement.clone()])),
                    safety: None,
                },
            ),
        );
        let marker = MarkerIr {
            id: MarkerId::new(0),
            identity: String::from("valid-input-marker"),
            kind: MarkerKindIr::PanicJustification,
            source_range: None,
            target: MarkerTargetIr::Call(CallId::new(0)),
            applicable_probing: vec![MarkerProbingIr::SourceCallsite],
            satisfactions: vec![MarkerSatisfactionIr {
                requirement: Some(String::from("valid_input")),
                reason: String::from("validated above"),
            }],
            requirements: vec![requirement],
        };
        let analysis = ir(vec![
            body(root, "workspace::root")
                .with_call(edge)
                .with_marker(marker),
        ]);

        let default_result =
            interpret(&analysis, &[report_root(root)], &SniffTestConfig::default());
        assert!(matches!(
            default_result[0].findings[0].kind,
            InterpretedFindingKind::DocumentedPanic { .. }
        ));

        let mut source_callsite = SniffTestConfig::default();
        source_callsite.analysis.marker_probing = MarkerProbing::SourceCallsite;
        assert!(
            interpret(&analysis, &[report_root(root)], &source_callsite)[0]
                .findings
                .is_empty()
        );
    }

    #[test]
    fn active_documentation_override_replaces_raw_contract_facts() {
        let root = id(1, 1);
        let target = id(2, 1);
        let analysis =
            ir(vec![body(root, "workspace::root").with_call(call(
                0,
                function_target(target, "dependency::overridden"),
            ))]);
        let mut config = SniffTestConfig::default();
        config.documentation.overrides = ContractDocOverrides::new(vec![(
            String::from("dependency::overridden"),
            String::from("# Panics\n\n- ready: the value must be ready"),
        )])
        .expect("valid override");

        let result = interpret(&analysis, &[report_root(root)], &config);
        let finding = &result[0].findings[0];

        assert!(matches!(
            finding.kind,
            InterpretedFindingKind::DocumentedPanic { .. }
        ));
        assert_eq!(finding.missing_requirements[0].name, "ready");
    }

    #[test]
    fn reports_raw_unsafe_operations_and_actual_unsafe_calls() {
        let root = id(1, 1);
        let target = id(1, 2);
        let mut unsafe_call = call(
            0,
            unsafe_function_target(target, "workspace::unsafe_target"),
        );
        unsafe_call.requires_unsafe = true;
        let analysis = ir(vec![
            body(root, "workspace::root")
                .with_call(unsafe_call)
                .with_effect(unsafe_effect(0, SafetyOpKind::DerefRawPointer)),
            body(target, "workspace::unsafe_target"),
        ]);

        let result = interpret(&analysis, &[report_root(root)], &SniffTestConfig::default());
        let kinds = result[0]
            .findings
            .iter()
            .map(|finding| &finding.kind)
            .collect::<Vec<_>>();

        assert!(kinds.iter().any(|kind| matches!(
            kind,
            InterpretedFindingKind::UnsafeOperation {
                kind: SafetyOpKind::DerefRawPointer
            }
        )));
        assert!(kinds.iter().any(|kind| matches!(
            kind,
            InterpretedFindingKind::SafetyCall {
                kind: InterpretedSafetyCallKind::Unsafe,
                ..
            }
        )));
    }

    #[test]
    fn opaque_indirect_boundary_is_reported_with_complete_analysis() {
        let root = id(1, 1);
        let mut edge = call(
            0,
            CallTargetIr::OpaqueBoundary {
                description: String::from(
                    "indirect call Binder { value: unsafe fn(), bound_vars: [] }",
                ),
                target: None,
            },
        );
        edge.kind = CallEdgeKindIr::IndirectCall;
        edge.requires_unsafe = true;
        let analysis = ir(vec![body(root, "workspace::root").with_call(edge)]);

        let result = interpret(&analysis, &[report_root(root)], &SniffTestConfig::default());
        let root = &result[0];

        let panic = root
            .findings
            .iter()
            .find(|finding| {
                matches!(
                    finding.kind,
                    InterpretedFindingKind::OpaquePanicBoundary { .. }
                )
            })
            .expect("the opaque panic boundary should be reported");
        assert!(matches!(
            &panic.kind,
            InterpretedFindingKind::OpaquePanicBoundary { description }
                if description == "indirect call through an unsafe function pointer"
        ));
        assert_eq!(
            panic
                .trace
                .steps
                .last()
                .and_then(|step| step.target_path.as_deref()),
            Some("indirect call through an unsafe function pointer")
        );
        assert!(root.findings.iter().any(|finding| matches!(
            finding.kind,
            InterpretedFindingKind::SafetyCall {
                kind: InterpretedSafetyCallKind::Unsafe,
                ..
            }
        )));
        assert!(root.completeness.panic.complete);
        assert!(root.completeness.safety.complete);
    }

    #[test]
    fn callable_attribution_selects_only_edges_for_the_active_mode() {
        let root = id(1, 1);
        let first = id(2, 1);
        let second = id(2, 2);
        let mut erasure = call(0, function_target(first, "dependency::erasure_sink"));
        erasure.applicable_attribution = vec![CallableAttributionIr::ErasureSites];
        let mut callsite = call(1, function_target(second, "dependency::callsite_sink"));
        callsite.applicable_attribution = vec![CallableAttributionIr::CallSites];
        let analysis = ir(vec![
            body(root, "workspace::root")
                .with_call(erasure)
                .with_call(callsite),
        ]);
        let mut config = SniffTestConfig::default();
        config.panics.panic_sink_namespaces = PathPatterns::new(vec![
            String::from("dependency::erasure_sink"),
            String::from("dependency::callsite_sink"),
        ])
        .expect("valid sink patterns");

        let erasure = interpret(&analysis, &[report_root(root)], &config);
        assert_eq!(
            erasure[0].findings[0]
                .target
                .as_ref()
                .expect("sink target")
                .path,
            "dependency::erasure_sink"
        );

        config.analysis.callable_edge_attribution = CallableEdgeAttribution::CallSites;
        let callsite = interpret(&analysis, &[report_root(root)], &config);
        assert_eq!(
            callsite[0].findings[0]
                .target
                .as_ref()
                .expect("sink target")
                .path,
            "dependency::callsite_sink"
        );
    }

    #[test]
    fn call_cycles_terminate_and_node_limit_marks_each_domain_incomplete() {
        let first = id(1, 1);
        let second = id(1, 2);
        let analysis = ir(vec![
            body(first, "workspace::first")
                .with_call(call(0, function_target(second, "workspace::second"))),
            body(second, "workspace::second")
                .with_call(call(0, function_target(first, "workspace::first")))
                .with_effect(assert_effect(0, CompilerAssertKind::BoundsCheck)),
        ]);

        let complete = interpret(
            &analysis,
            &[report_root(first)],
            &SniffTestConfig::default(),
        );
        assert!(complete[0].completeness.panic.complete);
        assert!(complete[0].findings.is_empty());

        let mut limited = SniffTestConfig::default();
        limited.analysis.node_limit = 1;
        let limited = interpret(&analysis, &[report_root(first)], &limited);
        assert!(!limited[0].completeness.panic.complete);
        assert!(!limited[0].completeness.safety.complete);
        assert_eq!(limited[0].completeness.panic.visited_bodies, 1);
        assert_eq!(limited[0].completeness.safety.visited_bodies, 1);
    }

    #[test]
    fn two_unique_cycle_bodies_fit_a_two_node_limit() {
        let first = id(1, 1);
        let second = id(1, 2);
        let analysis = ir(vec![
            body(first, "workspace::first")
                .with_call(call(0, function_target(second, "workspace::second"))),
            body(second, "workspace::second")
                .with_call(call(0, function_target(first, "workspace::first"))),
        ]);
        let mut config = SniffTestConfig::default();
        config.analysis.node_limit = 2;

        let result = interpret(&analysis, &[report_root(first)], &config);
        let root = &result[0];

        assert!(root.completeness.panic.complete);
        assert!(root.completeness.safety.complete);
        assert_eq!(root.completeness.panic.visited_bodies, 2);
        assert_eq!(root.completeness.safety.visited_bodies, 2);
    }

    #[test]
    fn deep_call_chain_is_interpreted_to_its_terminal_effect() {
        const BODY_COUNT: usize = 2_048;

        let last_local_id = u64::try_from(BODY_COUNT).expect("test body count fits in u64");
        let mut bodies = Vec::<FunctionBodyIr>::with_capacity(BODY_COUNT);
        for local_id in 1..last_local_id {
            let current = id(1, local_id);
            let next = id(1, local_id + 1);
            bodies.push(
                body(current, &format!("workspace::function_{local_id}"))
                    .with_call(call(
                        0,
                        function_target(next, &format!("workspace::function_{}", local_id + 1)),
                    ))
                    .into(),
            );
        }
        bodies.push(
            body(id(1, last_local_id), "workspace::last")
                .with_effect(assert_effect(0, CompilerAssertKind::BoundsCheck))
                .into(),
        );
        let analysis = ir(bodies);
        let mut config = SniffTestConfig::default();
        config.analysis.node_limit = BODY_COUNT;

        let result = interpret(&analysis, &[report_root(id(1, 1))], &config);
        let root = &result[0];

        assert!(root.completeness.panic.complete);
        assert_eq!(root.completeness.panic.visited_bodies, BODY_COUNT);
        assert!(root.findings.is_empty());
    }

    #[test]
    fn safety_documented_unsafe_body_suppresses_pointer_precondition_asserts() {
        let root = id(1, 1);
        let safety_contract = MarkerIr {
            id: MarkerId::new(0),
            identity: String::from("safety-contract"),
            kind: MarkerKindIr::SafetyContract,
            source_range: None,
            target: MarkerTargetIr::Function(root),
            applicable_probing: vec![
                MarkerProbingIr::SourceCallsite,
                MarkerProbingIr::MacroDefinitionFirst,
            ],
            satisfactions: Vec::new(),
            requirements: Vec::new(),
        };
        let analysis = ir(vec![
            body(root, "workspace::unsafe_root")
                .unsafe_function()
                .with_marker(safety_contract)
                .with_effect(assert_effect(0, CompilerAssertKind::NullPointerDereference)),
        ]);

        let result = interpret(&analysis, &[report_root(root)], &SniffTestConfig::default());

        assert!(result[0].findings.is_empty());
        assert!(result[0].completeness.panic.complete);
        assert!(result[0].completeness.safety.complete);
    }

    #[test]
    fn mixed_panic_and_safety_marker_ambiguity_stays_in_legacy_findings() {
        let root = id(1, 1);
        let helper = id(1, 2);
        let panic_marker = justification_marker(
            0,
            MarkerKindIr::PanicJustification,
            MarkerTargetIr::Call(CallId::new(0)),
            None,
        );
        let safety_marker = justification_marker(
            1,
            MarkerKindIr::SafetyJustification,
            MarkerTargetIr::Call(CallId::new(0)),
            None,
        );
        let analysis = ir(vec![
            body(root, "workspace::root")
                .with_call(call(0, function_target(helper, "workspace::helper")))
                .with_marker(panic_marker)
                .with_marker(safety_marker),
            body(helper, "workspace::helper")
                .with_effect(assert_effect(0, CompilerAssertKind::BoundsCheck))
                .with_effect(assert_effect(1, CompilerAssertKind::Overflow))
                .with_effect(unsafe_effect(2, SafetyOpKind::DerefRawPointer))
                .with_effect(unsafe_effect(3, SafetyOpKind::InlineAssembly)),
        ]);

        let result = interpret(&analysis, &[report_root(root)], &SniffTestConfig::default());
        let findings = &result[0].findings;

        assert_eq!(findings.len(), 2);
        assert!(findings.iter().any(|finding| matches!(
            finding.kind,
            InterpretedFindingKind::AmbiguousPanicMarker { effect_count: 2 }
        )));
        assert!(findings.iter().any(|finding| matches!(
            finding.kind,
            InterpretedFindingKind::AmbiguousSafetyMarker { effect_count: 2 }
        )));
    }

    #[test]
    fn ambiguous_marker_uses_the_shortest_canonical_trace() {
        let root = id(1, 1);
        let long = id(1, 2);
        let middle = id(1, 3);
        let lexical_later = id(1, 4);
        let lexical_first = id(1, 5);
        let mut long_marker = justification_marker(
            0,
            MarkerKindIr::PanicJustification,
            MarkerTargetIr::Call(CallId::new(0)),
            None,
        );
        long_marker.identity = String::from("shared-marker");
        let mut lexical_later_marker = justification_marker(
            1,
            MarkerKindIr::PanicJustification,
            MarkerTargetIr::Call(CallId::new(1)),
            None,
        );
        lexical_later_marker.identity = String::from("shared-marker");
        let mut lexical_first_marker = justification_marker(
            2,
            MarkerKindIr::PanicJustification,
            MarkerTargetIr::Call(CallId::new(2)),
            None,
        );
        lexical_first_marker.identity = String::from("shared-marker");
        let analysis = ir(vec![
            body(root, "workspace::root")
                .with_call(call(0, function_target(long, "workspace::long")))
                .with_call(call(
                    1,
                    function_target(lexical_later, "workspace::z_short"),
                ))
                .with_call(call(
                    2,
                    function_target(lexical_first, "workspace::a_short"),
                ))
                .with_marker(long_marker)
                .with_marker(lexical_later_marker)
                .with_marker(lexical_first_marker),
            body(long, "workspace::long")
                .with_call(call(0, function_target(middle, "workspace::middle"))),
            body(middle, "workspace::middle")
                .with_effect(assert_effect(0, CompilerAssertKind::BoundsCheck)),
            body(lexical_later, "workspace::z_short")
                .with_effect(assert_effect(0, CompilerAssertKind::Overflow)),
            body(lexical_first, "workspace::a_short")
                .with_effect(assert_effect(0, CompilerAssertKind::DivisionByZero)),
        ]);

        let result = interpret(&analysis, &[report_root(root)], &SniffTestConfig::default());
        let ambiguous = result[0]
            .findings
            .iter()
            .find(|finding| {
                matches!(
                    finding.kind,
                    InterpretedFindingKind::AmbiguousPanicMarker { effect_count: 3 }
                )
            })
            .expect("one shared marker should be reported as ambiguous");

        assert_eq!(ambiguous.trace.steps.len(), 2);
        assert_eq!(
            ambiguous.trace.steps[0].target_path.as_deref(),
            Some("workspace::a_short")
        );
    }

    #[test]
    fn duplicate_callable_endpoints_share_one_unambiguous_safety_group() {
        let root = id(1, 1);
        let erased_target = id(1, 2);
        let concrete_target = id(1, 3);
        let mut erased = call(
            0,
            unsafe_function_target(erased_target, "workspace::erased_target"),
        );
        erased.requires_unsafe = true;
        erased.safety_effect_group = Some(SafetyEffectGroupId::new(7));
        let mut concrete = call(
            1,
            unsafe_function_target(concrete_target, "workspace::concrete_target"),
        );
        concrete.requires_unsafe = true;
        concrete.safety_effect_group = Some(SafetyEffectGroupId::new(7));

        let erased_marker = justification_marker(
            0,
            MarkerKindIr::SafetyJustification,
            MarkerTargetIr::Call(CallId::new(0)),
            None,
        );
        let concrete_marker = justification_marker(
            1,
            MarkerKindIr::SafetyJustification,
            MarkerTargetIr::Call(CallId::new(1)),
            None,
        );
        let analysis = ir(vec![
            body(root, "workspace::root")
                .with_call(erased)
                .with_call(concrete)
                .with_marker(erased_marker)
                .with_marker(concrete_marker),
            body(erased_target, "workspace::erased_target").unsafe_function(),
            body(concrete_target, "workspace::concrete_target").unsafe_function(),
        ]);

        let result = interpret(&analysis, &[report_root(root)], &SniffTestConfig::default());

        assert!(result[0].findings.is_empty());
    }

    #[test]
    fn bridge_edges_traverse_erasure_targets_without_extra_boundaries() {
        let root = id(1, 1);
        let dyn_target = id(1, 2);
        let reified_target = id(1, 3);
        let mut dyn_cast = call(
            0,
            CallTargetIr::OpaqueBoundary {
                description: String::from("dyn cast bridge"),
                target: None,
            },
        );
        dyn_cast.kind = CallEdgeKindIr::DynObjectCast;
        let mut vtable = call(1, function_target(dyn_target, "workspace::dyn_target"));
        vtable.kind = CallEdgeKindIr::VTableEntry;
        vtable.applicable_attribution = vec![CallableAttributionIr::ErasureSites];
        let mut reify = call(
            2,
            unsafe_function_target(reified_target, "workspace::reified_target"),
        );
        reify.kind = CallEdgeKindIr::FnPointerReify;
        reify.requires_unsafe = true;
        let mut assert_bridge = call(
            3,
            CallTargetIr::OpaqueBoundary {
                description: String::from("assert bridge"),
                target: None,
            },
        );
        assert_bridge.kind = CallEdgeKindIr::Assert;
        let analysis = ir(vec![
            body(root, "workspace::root")
                .with_call(dyn_cast)
                .with_call(vtable)
                .with_call(reify)
                .with_call(assert_bridge)
                .with_effect(assert_effect(0, CompilerAssertKind::Overflow)),
            body(dyn_target, "workspace::dyn_target")
                .with_effect(assert_effect(0, CompilerAssertKind::BoundsCheck)),
            body(reified_target, "workspace::reified_target"),
        ]);

        let result = interpret(&analysis, &[report_root(root)], &SniffTestConfig::default());
        let findings = &result[0].findings;
        assert!(!findings.iter().any(|finding| matches!(
            finding.kind,
            InterpretedFindingKind::OpaquePanicBoundary { .. }
                | InterpretedFindingKind::SafetyCall { .. }
        )));
        assert!(findings.is_empty());
    }

    #[test]
    fn ignored_trusted_and_sink_namespace_policies_are_applied_to_raw_ir() {
        let root = id(1, 1);
        let ignored = id(2, 1);
        let trusted = id(2, 2);
        let sink = id(2, 3);
        let analysis = ir(vec![
            body(root, "workspace::root")
                .with_call(call(0, function_target(ignored, "dependency::ignored")))
                .with_call(call(1, function_target(trusted, "dependency::trusted")))
                .with_call(call(2, function_target(sink, "dependency::sink"))),
            body(ignored, "dependency::ignored")
                .with_effect(assert_effect(0, CompilerAssertKind::Overflow)),
            body(trusted, "dependency::trusted")
                .with_effect(assert_effect(0, CompilerAssertKind::BoundsCheck)),
            body(sink, "dependency::sink")
                .with_effect(assert_effect(0, CompilerAssertKind::DivisionByZero)),
        ]);
        let mut config = SniffTestConfig::default();
        config.panics.ignored_namespaces =
            PathPatterns::new(vec![String::from("dependency::ignored")])
                .expect("valid ignored pattern");
        config.panics.trusted_panic_boundary_namespaces =
            PathPatterns::new(vec![String::from("dependency::trusted")])
                .expect("valid trusted pattern");
        config.panics.panic_sink_namespaces =
            PathPatterns::new(vec![String::from("dependency::sink")]).expect("valid sink pattern");

        let result = interpret(&analysis, &[report_root(root)], &config);
        let panic_findings = result[0]
            .findings
            .iter()
            .filter(|finding| {
                matches!(
                    finding.kind,
                    InterpretedFindingKind::PanicSink
                        | InterpretedFindingKind::DocumentedPanic { .. }
                        | InterpretedFindingKind::OpaquePanicBoundary { .. }
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(panic_findings.len(), 1);
        assert!(matches!(
            panic_findings[0].kind,
            InterpretedFindingKind::PanicSink
        ));
    }

    #[test]
    fn raw_and_override_safety_contracts_become_named_call_obligations() {
        let root = id(1, 1);
        let raw = id(1, 2);
        let overridden = id(1, 3);
        let analysis = ir(vec![
            body(root, "workspace::root")
                .with_call(call(
                    0,
                    function_target_with_contracts(
                        raw,
                        "workspace::raw_safety",
                        FunctionContractsIr {
                            panic: None,
                            safety: Some(contract(vec![requirement(
                                "raw invariant",
                                "the raw invariant holds",
                            )])),
                        },
                    ),
                ))
                .with_call(call(
                    1,
                    function_target(overridden, "workspace::overridden_safety"),
                )),
            body(raw, "workspace::raw_safety"),
            body(overridden, "workspace::overridden_safety"),
        ]);
        let mut config = SniffTestConfig::default();
        config.documentation.overrides = ContractDocOverrides::new(vec![(
            String::from("workspace::overridden_safety"),
            String::from("# Safety\n\n- override invariant: it holds"),
        )])
        .expect("valid override");

        let result = interpret(&analysis, &[report_root(root)], &config);
        let mut missing = result[0]
            .findings
            .iter()
            .filter_map(|finding| match finding.kind {
                InterpretedFindingKind::SafetyCall {
                    kind: InterpretedSafetyCallKind::Obligation,
                    ..
                } => Some(finding.missing_requirements[0].name.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        missing.sort_unstable();

        assert_eq!(missing, ["override invariant", "raw invariant"]);
    }

    #[test]
    fn builtin_unsafe_call_is_satisfied_by_its_compiler_context() {
        let root = id(1, 1);
        let callee = id(1, 2);
        let mut compiler_call = call(
            0,
            function_target_with_contracts(
                callee,
                "workspace::compiler_runtime_helper",
                FunctionContractsIr {
                    panic: None,
                    safety: Some(contract(vec![requirement(
                        "runtime invariant",
                        "the compiler maintains the runtime invariant",
                    )])),
                },
            ),
        );
        compiler_call.inside_builtin_unsafe = true;
        let analysis = ir(vec![
            body(root, "workspace::root").with_call(compiler_call),
            body(callee, "workspace::compiler_runtime_helper"),
        ]);

        let result = interpret(&analysis, &[report_root(root)], &SniffTestConfig::default());

        assert!(
            !result[0]
                .findings
                .iter()
                .any(|finding| matches!(finding.kind, InterpretedFindingKind::SafetyCall { .. }))
        );
    }

    #[test]
    fn a_root_contract_is_a_silent_boundary_for_its_own_internal_effects() {
        let root = id(1, 1);
        let panic_contract = MarkerIr {
            id: MarkerId::new(0),
            identity: String::from("panic-contract"),
            kind: MarkerKindIr::PanicContract,
            source_range: None,
            target: MarkerTargetIr::Function(root),
            applicable_probing: vec![
                MarkerProbingIr::SourceCallsite,
                MarkerProbingIr::MacroDefinitionFirst,
            ],
            satisfactions: Vec::new(),
            requirements: Vec::new(),
        };
        let analysis = ir(vec![
            body(root, "workspace::root")
                .with_marker(panic_contract)
                .with_effect(assert_effect(0, CompilerAssertKind::BoundsCheck)),
        ]);

        let result = interpret(&analysis, &[report_root(root)], &SniffTestConfig::default());

        assert!(result[0].findings.is_empty());
        assert!(result[0].completeness.panic.complete);
    }

    fn report_root(function: FunctionId) -> InterpretationRoot {
        InterpretationRoot {
            function,
            path: String::from("workspace::root"),
            kind: ReportRootKind::Generic,
        }
    }

    fn ir<T: Into<FunctionBodyIr>>(functions: Vec<T>) -> ArtifactAnalysisIr {
        ArtifactAnalysisIr::new(functions.into_iter().map(Into::into).collect(), Vec::new())
            .expect("valid test IR")
    }

    fn ir_with_source<T: Into<FunctionBodyIr>>(functions: Vec<T>) -> ArtifactAnalysisIr {
        ArtifactAnalysisIr::new(
            functions.into_iter().map(Into::into).collect(),
            vec![source_file()],
        )
        .expect("valid test IR")
    }

    fn cache<T: Into<FunctionBodyIr>>(
        crate_name: &str,
        stable_crate_id: u64,
        functions: Vec<T>,
    ) -> ArtifactAnalysisCache {
        let facts = ArtifactFactIr {
            format_version: FACT_IR_FORMAT_VERSION,
            tables: Vec::new(),
            fact_index: Vec::new(),
            relation_index: Vec::new(),
        };
        ArtifactAnalysisCache::new_with_legacy(
            "test-tool",
            "test-rustc",
            ArtifactInfo {
                id: RustcArtifactId::new(stable_crate_id, format!("{stable_crate_id:032x}")),
                crate_name: crate_name.to_owned(),
            },
            Vec::new(),
            ir(functions),
            facts,
            &SchemaRegistry::new(),
        )
        .expect("valid test cache")
    }

    fn id(stable_crate_id: u64, local_id: u64) -> FunctionId {
        FunctionId::generic(definition_hash(stable_crate_id, local_id))
    }

    fn definition_hash(stable_crate_id: u64, local_id: u64) -> StableDefPathHash {
        serde_json::from_str(&format!("\"{stable_crate_id:016x}{local_id:016x}\""))
            .expect("valid definition hash")
    }

    fn instance_hash(value: u64) -> StableInstanceHash {
        serde_json::from_str(&format!("\"{value:032x}\"")).expect("valid instance hash")
    }

    fn source_file() -> SourceFileIr {
        SourceFileIr {
            id: SourceFileId::new("workspace-source"),
            filename: String::from("src/lib.rs"),
            content_hash: String::from("test-content-hash"),
            byte_len: 100,
        }
    }

    fn source_range(byte_start: u64, byte_end: u64) -> SourceRangeIr {
        SourceRangeIr {
            file: source_file().id,
            byte_start,
            byte_end,
        }
    }

    fn body(function: FunctionId, path: &str) -> TestBody {
        TestBody(FunctionBodyIr {
            function,
            provenance: FunctionBodyProvenanceIr::DefiningArtifact,
            display_path: path.to_owned(),
            attributes: FunctionAttributesIr {
                is_unsafe: false,
                is_exported: false,
                has_rust_body: true,
                is_foreign: false,
                namespace_candidates: vec![path.to_owned()],
            },
            source_range: None,
            calls: Vec::new(),
            effects: Vec::new(),
            markers: Vec::new(),
        })
    }

    struct TestBody(FunctionBodyIr);

    struct ManagedLookup<'a> {
        ir: &'a ArtifactAnalysisIr,
        stable_crate_ids: Vec<u64>,
    }

    impl FunctionLookup for ManagedLookup<'_> {
        fn function(
            &self,
            function: FunctionId,
        ) -> Option<crate::analysis::graph::LoadedFunction<'_>> {
            FunctionLookup::function(self.ir, function)
        }

        fn function_in_scope(
            &self,
            scope: &crate::analysis::graph::BodyScope,
            function: FunctionId,
        ) -> Option<crate::analysis::graph::LoadedFunction<'_>> {
            FunctionLookup::function_in_scope(self.ir, scope, function)
        }

        fn defining_source_body(
            &self,
            function: FunctionId,
        ) -> Option<crate::analysis::graph::LoadedFunction<'_>> {
            FunctionLookup::defining_source_body(self.ir, function)
        }

        fn manages_stable_crate_id(&self, stable_crate_id: u64) -> bool {
            self.stable_crate_ids.contains(&stable_crate_id)
        }
    }

    impl TestBody {
        fn with_call(mut self, call: CallEdgeIr) -> Self {
            self.0.calls.push(call);
            self
        }

        fn with_effect(mut self, effect: EffectFactIr) -> Self {
            self.0.effects.push(effect);
            self
        }

        fn with_marker(mut self, marker: MarkerIr) -> Self {
            self.0.markers.push(marker);
            self
        }

        fn unsafe_function(mut self) -> Self {
            self.0.attributes.is_unsafe = true;
            self
        }

        fn consumer_instantiation(mut self, consumer_stable_crate_id: u64) -> Self {
            self.0.provenance = FunctionBodyProvenanceIr::ConsumerInstantiation {
                consumer_stable_crate_id,
            };
            self
        }
    }

    impl From<TestBody> for FunctionBodyIr {
        fn from(body: TestBody) -> Self {
            body.0
        }
    }

    fn call(id: u32, target: CallTargetIr) -> CallEdgeIr {
        CallEdgeIr {
            id: CallId::new(id),
            call_site: CallSiteId::new(id),
            kind: CallEdgeKindIr::DirectCall,
            safety_effect_group: Some(SafetyEffectGroupId::new(id)),
            requires_unsafe: false,
            inside_builtin_unsafe: false,
            source_range: None,
            expanded_range: None,
            macro_expansions: Vec::new(),
            callee_range: None,
            applicable_attribution: vec![
                CallableAttributionIr::ErasureSites,
                CallableAttributionIr::CallSites,
            ],
            callable_keys: Vec::new(),
            source_target: None,
            target,
        }
    }

    fn function_target(function: FunctionId, path: &str) -> CallTargetIr {
        function_target_with_contracts(function, path, FunctionContractsIr::default())
    }

    fn unsafe_function_target(function: FunctionId, path: &str) -> CallTargetIr {
        let mut call_target =
            function_target_with_contracts(function, path, FunctionContractsIr::default());
        let CallTargetIr::Function(target) = &mut call_target else {
            unreachable!("helper always creates a function target");
        };
        target.attributes.is_unsafe = true;
        call_target
    }

    fn function_target_with_contracts(
        function: FunctionId,
        path: &str,
        contracts: FunctionContractsIr,
    ) -> CallTargetIr {
        CallTargetIr::Function(FunctionTargetIr {
            function,
            display_path: path.to_owned(),
            attributes: FunctionAttributesIr {
                is_unsafe: false,
                is_exported: false,
                has_rust_body: true,
                is_foreign: false,
                namespace_candidates: vec![path.to_owned()],
            },
            contracts,
        })
    }

    fn contract(requirements: Vec<ContractRequirementIr>) -> RawContractIr {
        RawContractIr {
            source_range: None,
            requirements,
        }
    }

    fn requirement(name: &str, condition: &str) -> ContractRequirementIr {
        ContractRequirementIr {
            name: name.to_owned(),
            condition: condition.to_owned(),
            source_range: None,
        }
    }

    fn assert_effect(id: u32, kind: CompilerAssertKind) -> EffectFactIr {
        EffectFactIr {
            id: EffectId::new(id),
            safety_effect_group: None,
            source_range: None,
            expanded_range: None,
            macro_expansions: Vec::new(),
            kind: EffectKindIr::CompilerAssert { kind },
        }
    }

    fn unsafe_effect(id: u32, kind: SafetyOpKind) -> EffectFactIr {
        EffectFactIr {
            id: EffectId::new(id),
            safety_effect_group: Some(SafetyEffectGroupId::new(id)),
            source_range: None,
            expanded_range: None,
            macro_expansions: Vec::new(),
            kind: EffectKindIr::UnsafeOperation { kind },
        }
    }

    fn justification_marker(
        id: u32,
        kind: MarkerKindIr,
        target: MarkerTargetIr,
        requirement: Option<&str>,
    ) -> MarkerIr {
        MarkerIr {
            id: MarkerId::new(id),
            identity: format!("marker-{id}"),
            kind,
            source_range: None,
            target,
            applicable_probing: vec![
                MarkerProbingIr::SourceCallsite,
                MarkerProbingIr::MacroDefinitionFirst,
            ],
            satisfactions: vec![MarkerSatisfactionIr {
                requirement: requirement.map(str::to_owned),
                reason: String::from("justified"),
            }],
            requirements: Vec::new(),
        }
    }
}
