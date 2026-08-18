#[allow(
    clippy::wildcard_imports,
    reason = "the engine is the private implementation half of its parent traversal contract"
)]
use super::*;
use std::rc::Rc;

type VisitKey = (ScopedEntityRef, BTreeSet<ScopedEntityRef>);
type DefiningSourceKey = (SourceAnchorKey, Option<SourceAnchorKey>);
type RawTargetShape = Vec<(CallTargetRole, crate::namespace::StableDefPathHash)>;

pub(super) fn validate_unsafe_operation_path_shape(frame_count: usize, link_count: usize) -> bool {
    frame_count != 0 && link_count.checked_add(1) == Some(frame_count)
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SemanticShapeKey {
    kind: CallKind,
    raw_targets: RawTargetShape,
    opaque_description: Option<String>,
}

type ConsumerSourcePlanKey = (
    ScopedEntityId<FunctionEntity>,
    ScopedEntityId<FunctionEntity>,
);

struct BodyWork<'a> {
    body: &'a ScopedProgramEntity<FunctionEntity>,
    callable: &'a ScopedProgramEntity<CallableEntity>,
    carried_markers: PreparedMarkerState,
    path: PreparedPathId,
    is_root: bool,
}

#[derive(Clone)]
struct OccurrenceWork<'a> {
    call_site: &'a ScopedProgramEntity<CallSiteEntity>,
    occurrence: &'a ScopedProgramEntity<CallOccurrenceEntity>,
    safety_group: &'a ScopedProgramEntity<SafetyEffectGroupEntity>,
    source_anchors: Vec<ResolvedCallSourceAnchor>,
    macro_frames: Vec<ResolvedCallMacroFrame>,
    carried_markers: PreparedMarkerState,
    consumer_source: Option<Rc<ConsumerSourcePlan<'a>>>,
    path: PreparedPathId,
}

#[derive(Clone)]
struct ConsumerSourcePlan<'a> {
    buckets_by_source: BTreeMap<DefiningSourceKey, DefiningSourceBucket<'a>>,
}

struct PreparedConsumerSource<'a> {
    plan: Rc<ConsumerSourcePlan<'a>>,
    defining_body: &'a ScopedProgramEntity<FunctionEntity>,
    defining_path: PreparedPathId,
}

#[derive(Clone, Default)]
struct DefiningSourceBucket<'a> {
    by_effective_definition:
        BTreeMap<crate::namespace::StableDefPathHash, Vec<DefiningOccurrenceRoute<'a>>>,
    by_complete_shape: BTreeMap<SemanticShapeKey, Vec<DefiningOccurrenceRoute<'a>>>,
    actual_calls: Vec<DefiningOccurrenceRoute<'a>>,
}

#[derive(Clone)]
struct DefiningOccurrenceRoute<'a> {
    call_site: &'a ScopedProgramEntity<CallSiteEntity>,
    occurrence: &'a ScopedProgramEntity<CallOccurrenceEntity>,
    safety_group: &'a ScopedProgramEntity<SafetyEffectGroupEntity>,
    source_anchors: Vec<ResolvedCallSourceAnchor>,
    targets: Vec<DefiningTargetRoute<'a>>,
}

#[derive(Clone)]
struct DefiningTargetRoute<'a> {
    role: CallTargetRole,
    callable: &'a ScopedProgramEntity<CallableEntity>,
    relation: ScopedRelationRef,
}

#[derive(Clone)]
struct PreparedCallReconciliation<'a> {
    candidates: Vec<DefiningMarkerCandidate>,
    accepted_markers: PreparedMarkerState,
    defining_source_target: Option<PreparedPolicyTarget<'a>>,
    defining_target: Option<PreparedPolicyTarget<'a>>,
}

struct PreparedSelectedReconciliation<'r, 'a> {
    routes: Vec<&'r DefiningOccurrenceRoute<'a>>,
    paths: Vec<PreparedPathId>,
    candidates: Vec<DefiningMarkerCandidate>,
    marker_states: Vec<PreparedMarkerState>,
}

struct PreparedReconciliationAuthorities<'a> {
    defining_source_target: Option<PreparedPolicyTarget<'a>>,
    defining_target: Option<PreparedPolicyTarget<'a>>,
}

#[derive(Clone)]
struct PendingInvocation<'a> {
    call_site: &'a ScopedProgramEntity<CallSiteEntity>,
    occurrence: &'a ScopedProgramEntity<CallOccurrenceEntity>,
    safety_group: &'a ScopedProgramEntity<SafetyEffectGroupEntity>,
    source_anchors: Vec<ResolvedCallSourceAnchor>,
    macro_frames: Vec<ResolvedCallMacroFrame>,
    inherited_markers: PreparedMarkerState,
    attached_marker_candidates: PreparedMarkerState,
    active_markers: PreparedMarkerState,
    reconciliation: Option<PreparedCallReconciliation<'a>>,
    path: PreparedPathId,
}

#[derive(Clone)]
struct ReachedCallableEvidence<'a> {
    occurrence: &'a ScopedProgramEntity<CallOccurrenceEntity>,
    callable: &'a ScopedProgramEntity<CallableEntity>,
    key: CallableKey,
    kind: CallableResolutionKind,
    path: PreparedPathId,
    reach_order: usize,
}

#[derive(Clone)]
struct PreparedPolicyTarget<'a> {
    authority: ReconciledCallTargetAuthority,
    role: CallTargetRole,
    callable: &'a ScopedProgramEntity<CallableEntity>,
    path: PreparedPathId,
}

type PendingInvocationKey = (
    ScopedEntityId<CallOccurrenceEntity>,
    BTreeSet<ScopedEntityRef>,
);
type ReachedEvidenceKey = (CallableKey, ScopedEntityId<CallableEntity>);
type SyntheticResolutionKey = (
    ScopedEntityId<CallOccurrenceEntity>,
    BTreeSet<ScopedEntityRef>,
    ScopedEntityId<CallableEntity>,
);

struct EffectWork<'a> {
    effect: &'a ScopedProgramEntity<EffectSiteEntity>,
    source_anchors: Vec<ResolvedEffectSourceAnchor>,
    macro_frames: Vec<ResolvedEffectMacroFrame>,
    carried_markers: PreparedMarkerState,
    path: PreparedPathId,
}

struct UnsafeOperationWork<'a> {
    operation: &'a ScopedProgramEntity<UnsafeOperationEntity>,
    owner: &'a ScopedProgramEntity<FunctionEntity>,
    owner_relation: ScopedRelationRef,
    safety_group: &'a ScopedProgramEntity<SafetyEffectGroupEntity>,
    safety_group_relation: ScopedRelationRef,
    source_anchors: Vec<ResolvedUnsafeOperationSourceAnchor>,
    macro_frames: Vec<ResolvedUnsafeOperationMacroFrame>,
    carried_markers: PreparedMarkerState,
    path: PreparedPathId,
}

#[derive(Clone)]
struct UnsafeOperationRoute<'a> {
    operation: &'a ScopedProgramEntity<UnsafeOperationEntity>,
    owner_relation: ScopedRelationRef,
    safety_group: &'a ScopedProgramEntity<SafetyEffectGroupEntity>,
    safety_group_relation: ScopedRelationRef,
    source_anchors: Vec<ResolvedUnsafeOperationSourceAnchor>,
    macro_frames: Vec<ResolvedUnsafeOperationMacroFrame>,
    path: UnsafeOperationPath,
}

#[derive(Clone)]
enum UnsafeOperationPath {
    Direct(ScopedRelationRef),
    Macro {
        entry: ScopedRelationRef,
        links: Vec<ScopedRelationRef>,
        exit: ScopedRelationRef,
        frame_ids: Vec<ScopedEntityRef>,
    },
}

enum Work<'a> {
    Body(BodyWork<'a>),
    CallableResolution(PendingInvocation<'a>, ReachedCallableEvidence<'a>),
    Effect(EffectWork<'a>),
    UnsafeOperation(UnsafeOperationWork<'a>),
    Occurrence(OccurrenceWork<'a>),
    Exit(VisitKey),
}

struct TraversalEngine<'a, 'facts, P: RootProgramTraversalPolicy> {
    workspace: &'a WorkspaceFactView<'facts>,
    index: &'a WorkspaceProgramIndex,
    resolver: &'a VerifiedDefiningScopeMap,
    request: &'a RootProgramTraversalRequest,
    policy: &'a mut P,
    root: EvaluationRoot,
    paths: PreparedPathArena,
    work: Vec<Work<'a>>,
    visited: BTreeSet<VisitKey>,
    active: BTreeSet<VisitKey>,
    consumer_source_plans: BTreeMap<ConsumerSourcePlanKey, Rc<ConsumerSourcePlan<'a>>>,
    unsafe_operation_routes:
        BTreeMap<ScopedEntityId<FunctionEntity>, Rc<Vec<UnsafeOperationRoute<'a>>>>,
    reached_evidence: BTreeMap<CallableKey, Vec<ReachedCallableEvidence<'a>>>,
    reached_evidence_seen: BTreeSet<ReachedEvidenceKey>,
    pending_invocations: BTreeMap<CallableKey, Vec<PendingInvocation<'a>>>,
    pending_invocation_seen: BTreeSet<PendingInvocationKey>,
    scheduled_resolutions: BTreeSet<SyntheticResolutionKey>,
    next_evidence_order: usize,
    expanded: usize,
    order: u64,
    composition_edges: BTreeSet<ProgramCompositionEdge>,
    callable_resolutions: Vec<PreparedCallableResolution>,
    consumer_body_sources: Vec<PreparedConsumerBodySource>,
    consumer_reconciliations: Vec<PreparedConsumerOccurrenceReconciliation>,
    body_visits: Vec<PreparedBodyVisit>,
    effect_visits: Vec<PreparedEffectVisit>,
    unsafe_operation_visits: Vec<PreparedUnsafeOperationVisit>,
    occurrence_visits: Vec<PreparedOccurrenceVisit>,
    followed_calls: Vec<PreparedFollowedCall>,
    body_boundaries: Vec<PreparedBodyBoundary<P::Boundary>>,
    call_boundaries: Vec<PreparedCallBoundary<P::Boundary>>,
    outcomes: Vec<PreparedTraversalOutcome>,
    #[cfg(test)]
    consumer_reconciliation_metrics: ConsumerReconciliationMetrics,
}

#[allow(
    clippy::type_complexity,
    reason = "the result preserves the policy's boundary and structured error types"
)]
pub(super) fn prepare<P: RootProgramTraversalPolicy>(
    workspace: &WorkspaceFactView<'_>,
    index: &WorkspaceProgramIndex,
    resolver: &VerifiedDefiningScopeMap,
    request: &RootProgramTraversalRequest,
    policy: &mut P,
) -> Result<PreparedRootProgramTraversal<P::Boundary, P::Error>, RootProgramTraversalError<P::Error>>
{
    index
        .validate_workspace(workspace)
        .map_err(RootProgramTraversalError::Index)?;
    resolver
        .validate_against(workspace, index)
        .map_err(RootProgramTraversalError::AuthorityMap)?;

    let root_candidate = index
        .body_candidates(&request.root_scope, &request.root_function)
        .map_err(RootProgramTraversalError::Index)?
        .into_iter()
        .next()
        .ok_or_else(|| RootProgramTraversalError::UnknownRoot {
            scope: request.root_scope.clone(),
            function: request.root_function,
        })?;
    let root_body = root_candidate.body();
    let root_callable = callable_for_body(index, root_body)?;
    let root = EvaluationRoot::new(request.domain.clone(), root_body.reference().clone());
    let mut engine = TraversalEngine {
        workspace,
        index,
        resolver,
        request,
        policy,
        paths: PreparedPathArena::new(root.entity.clone()),
        root,
        work: vec![Work::Body(BodyWork {
            body: root_body,
            callable: root_callable,
            carried_markers: PreparedMarkerState::default(),
            path: PreparedPathArena::root(),
            is_root: true,
        })],
        visited: BTreeSet::new(),
        active: BTreeSet::new(),
        consumer_source_plans: BTreeMap::new(),
        unsafe_operation_routes: BTreeMap::new(),
        reached_evidence: BTreeMap::new(),
        reached_evidence_seen: BTreeSet::new(),
        pending_invocations: BTreeMap::new(),
        pending_invocation_seen: BTreeSet::new(),
        scheduled_resolutions: BTreeSet::new(),
        next_evidence_order: 0,
        expanded: 0,
        order: 0,
        composition_edges: BTreeSet::new(),
        callable_resolutions: Vec::new(),
        consumer_body_sources: Vec::new(),
        consumer_reconciliations: Vec::new(),
        body_visits: Vec::new(),
        effect_visits: Vec::new(),
        unsafe_operation_visits: Vec::new(),
        occurrence_visits: Vec::new(),
        followed_calls: Vec::new(),
        body_boundaries: Vec::new(),
        call_boundaries: Vec::new(),
        outcomes: Vec::new(),
        #[cfg(test)]
        consumer_reconciliation_metrics: ConsumerReconciliationMetrics::default(),
    };
    engine.run()?;
    Ok(engine.finish())
}

fn callable_for_body<'a, E: Error>(
    index: &'a WorkspaceProgramIndex,
    body: &'a ScopedProgramEntity<FunctionEntity>,
) -> Result<&'a ScopedProgramEntity<CallableEntity>, RootProgramTraversalError<E>> {
    index
        .exact_callable(body.reference().scope(), body.data().key())
        .ok_or_else(|| {
            RootProgramTraversalError::Index(WorkspaceProgramIndexError::InvalidQuery {
                reason: format!(
                    "selected body {:?} has no exact callable metadata in `{}`",
                    body.data().key(),
                    body.reference().scope()
                ),
            })
        })
}

impl<'a, P: RootProgramTraversalPolicy> TraversalEngine<'a, '_, P> {
    fn run(&mut self) -> Result<(), RootProgramTraversalError<P::Error>> {
        while let Some(work) = self.work.pop() {
            match work {
                Work::Body(body) => self.process_body(&body)?,
                Work::CallableResolution(invocation, evidence) => {
                    self.process_callable_resolution(invocation, &evidence)?;
                }
                Work::Effect(effect) => self.process_effect(effect)?,
                Work::UnsafeOperation(operation) => self.process_unsafe_operation(operation)?,
                Work::Occurrence(occurrence) => self.process_occurrence(occurrence)?,
                Work::Exit(key) => {
                    self.active.remove(&key);
                }
            }
        }
        Ok(())
    }

    fn finish(self) -> PreparedRootProgramTraversal<P::Boundary, P::Error> {
        PreparedRootProgramTraversal {
            workspace: self.workspace.identity(),
            root: self.root,
            paths: self.paths,
            composition_edges: self.composition_edges,
            callable_resolutions: self.callable_resolutions,
            consumer_body_sources: self.consumer_body_sources,
            consumer_reconciliations: self.consumer_reconciliations,
            body_visits: self.body_visits,
            effect_visits: self.effect_visits,
            unsafe_operation_visits: self.unsafe_operation_visits,
            occurrence_visits: self.occurrence_visits,
            followed_calls: self.followed_calls,
            body_boundaries: self.body_boundaries,
            call_boundaries: self.call_boundaries,
            outcomes: self.outcomes,
            #[cfg(test)]
            consumer_reconciliation_metrics: self.consumer_reconciliation_metrics,
            error: PhantomData,
        }
    }

    fn process_body(
        &mut self,
        body: &BodyWork<'a>,
    ) -> Result<(), RootProgramTraversalError<P::Error>> {
        let key = (
            body.body.reference().clone(),
            body.carried_markers.signature(),
        );
        if self.active.contains(&key) {
            self.push_outcome(TraversalOutcomeKind::Cycle, body.path)?;
            return Ok(());
        }
        if self.visited.contains(&key) {
            self.push_outcome(TraversalOutcomeKind::Deduplicated, body.path)?;
            return Ok(());
        }
        // Every exact `(body, propagated-call-marker-state)` is policy-owned once.
        // This also deduplicates repeated boundaries, ignores, and budget drops.
        self.visited.insert(key.clone());

        let active_markers = body.carried_markers.clone();
        let endpoint_marker_candidates = self.function_marker_candidates(body.body, body.path)?;
        let policy_markers = active_markers.policy_values();
        let endpoint_policy_markers = endpoint_marker_candidates.policy_values();
        let decision = self
            .policy
            .decide_body(&BodyPolicyContext {
                body: body.body,
                callable: body.callable,
                active_marker_claims: &policy_markers,
                endpoint_marker_candidates: &endpoint_policy_markers,
                is_root: body.is_root,
            })
            .map_err(|source| RootProgramTraversalError::Policy {
                stage: "body traversal decision",
                source,
            })?;

        match decision {
            BodyTraversalDecision::Boundary(payload) => {
                let order = self.next_order()?;
                self.body_boundaries.push(PreparedBodyBoundary {
                    order,
                    body: body.body.id(),
                    body_data: body.body.data().clone(),
                    callable: body.callable.id(),
                    callable_data: body.callable.data().clone(),
                    active_markers,
                    endpoint_marker_candidates,
                    payload,
                    path: body.path,
                });
            }
            BodyTraversalDecision::Ignore => {
                self.push_outcome(TraversalOutcomeKind::Ignored, body.path)?;
            }
            BodyTraversalDecision::Expand => {
                if self.expanded >= self.request.node_budget {
                    self.push_outcome(
                        TraversalOutcomeKind::BudgetExceeded {
                            limit: self.request.node_budget,
                        },
                        body.path,
                    )?;
                    return Ok(());
                }
                self.expanded += 1;
                self.active.insert(key.clone());
                let order = self.next_order()?;
                self.body_visits.push(PreparedBodyVisit {
                    order,
                    body: body.body.id(),
                    data: body.body.data().clone(),
                    active_markers,
                    endpoint_marker_candidates,
                    path: body.path,
                });
                let consumer_source = self.prepare_consumer_source(body.body, body.path)?;
                let effects = self.effects_for_body(body.body, body.path, &body.carried_markers)?;
                let mut unsafe_operations =
                    self.unsafe_operations_for_body(body.body, body.path, &body.carried_markers)?;
                if let Some(source) = &consumer_source {
                    unsafe_operations.extend(self.unsafe_operations_for_body(
                        source.defining_body,
                        source.defining_path,
                        &body.carried_markers,
                    )?);
                }
                let occurrences = self.occurrences_for_body(
                    body.body,
                    body.path,
                    &body.carried_markers,
                    consumer_source.as_ref().map(|source| &source.plan),
                )?;
                self.work.push(Work::Exit(key));
                self.work
                    .extend(occurrences.into_iter().rev().map(Work::Occurrence));
                self.work.extend(
                    unsafe_operations
                        .into_iter()
                        .rev()
                        .map(Work::UnsafeOperation),
                );
                self.work
                    .extend(effects.into_iter().rev().map(Work::Effect));
            }
        }
        Ok(())
    }

    fn process_effect(
        &mut self,
        effect: EffectWork<'a>,
    ) -> Result<(), RootProgramTraversalError<P::Error>> {
        let inherited_markers = effect.carried_markers;
        let attached_marker_candidates =
            self.effect_marker_candidates(effect.effect, effect.path)?;
        let mut active_markers = inherited_markers.clone();
        active_markers.add_new(&attached_marker_candidates);
        let order = self.next_order()?;
        self.effect_visits.push(PreparedEffectVisit {
            order,
            effect: effect.effect.id(),
            data: effect.effect.data().clone(),
            source_anchors: effect.source_anchors,
            macro_frames: effect.macro_frames,
            inherited_markers,
            attached_marker_candidates,
            active_markers,
            path: effect.path,
        });
        Ok(())
    }

    fn process_unsafe_operation(
        &mut self,
        operation: UnsafeOperationWork<'a>,
    ) -> Result<(), RootProgramTraversalError<P::Error>> {
        let inherited_markers = operation.carried_markers;
        let attached_marker_candidates =
            self.unsafe_operation_marker_candidates(operation.operation, operation.path)?;
        let mut active_markers = inherited_markers.clone();
        active_markers.add_new(&attached_marker_candidates);
        let order = self.next_order()?;
        self.unsafe_operation_visits
            .push(PreparedUnsafeOperationVisit {
                order,
                operation: operation.operation.id(),
                data: operation.operation.data().clone(),
                owner: operation.owner.id(),
                owner_data: operation.owner.data().clone(),
                owner_relation: operation.owner_relation,
                safety_group: operation.safety_group.id(),
                safety_group_data: operation.safety_group.data().clone(),
                safety_group_relation: operation.safety_group_relation,
                source_anchors: operation.source_anchors,
                macro_frames: operation.macro_frames,
                inherited_markers,
                attached_marker_candidates,
                active_markers,
                path: operation.path,
            });
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one occurrence decision validates and retains the complete policy context atomically"
    )]
    fn process_occurrence(
        &mut self,
        occurrence: OccurrenceWork<'a>,
    ) -> Result<(), RootProgramTraversalError<P::Error>> {
        let inherited_markers = occurrence.carried_markers.clone();
        let attached_marker_candidates =
            self.call_marker_candidates(occurrence.occurrence, occurrence.path)?;
        let mut active_markers = inherited_markers.clone();
        active_markers.add_new(&attached_marker_candidates);
        let order = self.next_order()?;
        let kind = occurrence.occurrence.data().kind();
        let is_callable_evidence = matches!(
            kind,
            CallKind::FnPointerReify | CallKind::ClosureFnPointerReify | CallKind::VTableEntry
        );
        let registers_callable_evidence =
            is_callable_evidence && self.request.attribution == CallAttributionRole::CallSite;
        let is_structural = matches!(
            kind,
            CallKind::MacroExpansion | CallKind::DynObjectCast | CallKind::Assert
        );
        let reconciliation = if registers_callable_evidence || is_structural {
            None
        } else {
            self.prepare_consumer_reconciliations(&occurrence)?
        };
        if let Some(reconciliation) = &reconciliation {
            active_markers.add_new(&reconciliation.accepted_markers);
        }
        self.occurrence_visits.push(PreparedOccurrenceVisit {
            order,
            occurrence: occurrence.occurrence.id(),
            data: occurrence.occurrence.data().clone(),
            source_anchors: occurrence.source_anchors.clone(),
            macro_frames: occurrence.macro_frames.clone(),
            inherited_markers: inherited_markers.clone(),
            attached_marker_candidates: attached_marker_candidates.clone(),
            active_markers: active_markers.clone(),
            path: occurrence.path,
        });

        if registers_callable_evidence {
            return self.register_callable_evidence(occurrence.occurrence, occurrence.path);
        }
        if is_structural {
            self.push_outcome(TraversalOutcomeKind::Ignored, occurrence.path)?;
            return Ok(());
        }
        let pending = PendingInvocation {
            call_site: occurrence.call_site,
            occurrence: occurrence.occurrence,
            safety_group: occurrence.safety_group,
            source_anchors: occurrence.source_anchors,
            macro_frames: occurrence.macro_frames,
            inherited_markers,
            attached_marker_candidates,
            active_markers,
            reconciliation,
            path: occurrence.path,
        };
        let targets = self.persisted_targets(&pending, false)?;
        let raw_work_start = self.work.len();
        self.process_call_policy(
            pending.clone(),
            kind,
            ProgramCallResolution::Persisted,
            &targets,
            occurrence.path,
        )?;
        let raw_work = self.work.split_off(raw_work_start);
        if matches!(
            kind,
            CallKind::DirectCall | CallKind::TailCall | CallKind::IndirectCall
        ) {
            self.register_pending_invocation(&pending)?;
        }
        // Policy observes the raw call before synthetic resolutions, while DFS
        // still expands the raw selected body before any synthetic body.
        self.work.extend(raw_work);
        Ok(())
    }

    fn select_target<'b>(
        targets: &'b [PreparedPolicyTarget<'a>],
        selection: &CallTargetSelection,
    ) -> Result<&'b PreparedPolicyTarget<'a>, RootProgramTraversalError<P::Error>> {
        for target in targets {
            if target.role != selection.role || target.authority != selection.authority {
                continue;
            }
            if target.callable.id() == selection.callable {
                return Ok(target);
            }
        }
        Err(RootProgramTraversalError::InvalidPolicyDecision {
            reason: format!(
                "selection {selection:?} is not a member of the active exact target bundle"
            ),
        })
    }

    fn persisted_targets(
        &mut self,
        invocation: &PendingInvocation<'a>,
        source_contract_only: bool,
    ) -> Result<Vec<PreparedPolicyTarget<'a>>, RootProgramTraversalError<P::Error>> {
        let scope = invocation.occurrence.reference().scope();
        let indexed = self
            .index
            .call_targets(scope, invocation.occurrence.data().key())
            .map_err(RootProgramTraversalError::Index)?
            .to_vec();
        let mut targets = Vec::with_capacity(indexed.len());
        for target in indexed {
            if source_contract_only && target.role() != CallTargetRole::SourceContract {
                continue;
            }
            let callable = self
                .index
                .exact_callable(scope, &target.callable())
                .ok_or_else(|| {
                    RootProgramTraversalError::Index(WorkspaceProgramIndexError::InvalidQuery {
                        reason: format!(
                            "call target {:?} is unavailable in `{scope}`",
                            target.callable()
                        ),
                    })
                })?;
            let path = self.append_artifact(
                invocation.path,
                &invocation.occurrence.id().erase(),
                callable.id().erase(),
                target.relation().clone(),
            )?;
            targets.push(PreparedPolicyTarget {
                authority: ReconciledCallTargetAuthority::ConsumerRaw,
                role: target.role(),
                callable,
                path,
            });
        }
        Ok(targets)
    }

    fn process_call_policy(
        &mut self,
        invocation: PendingInvocation<'a>,
        effective_kind: CallKind,
        resolution: ProgramCallResolution,
        targets: &[PreparedPolicyTarget<'a>],
        base_path: PreparedPathId,
    ) -> Result<(), RootProgramTraversalError<P::Error>> {
        let policy_targets = targets
            .iter()
            .map(|target| CallTargetPolicyCandidate {
                role: target.role,
                callable: target.callable,
            })
            .collect::<Vec<_>>();
        let mut selectable_targets = targets.to_vec();
        let policy_reconciliation = policy_reconciliation_context(
            invocation.reconciliation.as_ref(),
            targets,
            &mut selectable_targets,
        );
        let inherited_policy_markers = invocation.inherited_markers.policy_values();
        let attached_policy_markers = invocation.attached_marker_candidates.policy_values();
        let active_policy_markers = invocation.active_markers.policy_values();
        let decision = self
            .policy
            .decide_call(&CallPolicyContext {
                call_site: invocation.call_site,
                occurrence: invocation.occurrence,
                safety_group: invocation.safety_group,
                effective_kind,
                targets: &policy_targets,
                resolution: resolution.clone(),
                reconciliation: policy_reconciliation,
                inherited_marker_claims: &inherited_policy_markers,
                attached_marker_candidates: &attached_policy_markers,
                active_marker_claims: &active_policy_markers,
            })
            .map_err(|source| RootProgramTraversalError::Policy {
                stage: "call traversal decision",
                source,
            })?;

        match decision {
            CallTraversalDecision::Ignore => {
                self.push_outcome(TraversalOutcomeKind::Ignored, base_path)?;
            }
            CallTraversalDecision::Boundary { target, payload } => {
                let selected = target
                    .as_ref()
                    .map(|selection| Self::select_target(&selectable_targets, selection))
                    .transpose()?;
                let (path, target_data) = selected.map_or((base_path, None), |selected| {
                    (selected.path, Some(selected.callable.data().clone()))
                });
                let order = self.next_order()?;
                self.call_boundaries.push(PreparedCallBoundary {
                    order,
                    occurrence: invocation.occurrence.id(),
                    occurrence_data: invocation.occurrence.data().clone(),
                    call_site: invocation.call_site.id(),
                    call_site_data: invocation.call_site.data().clone(),
                    safety_group: invocation.safety_group.id(),
                    safety_group_data: invocation.safety_group.data().clone(),
                    effective_kind,
                    resolution,
                    source_anchors: invocation.source_anchors,
                    macro_frames: invocation.macro_frames,
                    target,
                    target_data,
                    inherited_markers: invocation.inherited_markers,
                    attached_marker_candidates: invocation.attached_marker_candidates,
                    active_markers: invocation.active_markers,
                    payload,
                    path,
                });
            }
            CallTraversalDecision::Follow(selection) => {
                let selected = Self::select_target(&selectable_targets, &selection)?;
                let selected_callable = selected.callable;
                let selected_path = selected.path;
                let active_markers = invocation.active_markers.clone();
                let order = self.next_order()?;
                self.followed_calls.push(PreparedFollowedCall {
                    order,
                    occurrence: invocation.occurrence.id(),
                    occurrence_data: invocation.occurrence.data().clone(),
                    call_site: invocation.call_site.id(),
                    call_site_data: invocation.call_site.data().clone(),
                    safety_group: invocation.safety_group.id(),
                    safety_group_data: invocation.safety_group.data().clone(),
                    effective_kind,
                    resolution,
                    source_anchors: invocation.source_anchors,
                    macro_frames: invocation.macro_frames,
                    target: selection,
                    target_data: selected_callable.data().clone(),
                    inherited_markers: invocation.inherited_markers,
                    attached_marker_candidates: invocation.attached_marker_candidates,
                    active_markers: invocation.active_markers,
                    path: selected_path,
                });
                self.follow_callable(selected_callable, selected_path, active_markers)?;
            }
        }
        Ok(())
    }

    fn register_callable_evidence(
        &mut self,
        occurrence: &'a ScopedProgramEntity<CallOccurrenceEntity>,
        evidence_path: PreparedPathId,
    ) -> Result<(), RootProgramTraversalError<P::Error>> {
        let records = self
            .index
            .callable_evidence_at(occurrence.reference().scope(), occurrence.data().key())
            .map_err(RootProgramTraversalError::Index)?
            .to_vec();
        let mut scheduled = Vec::new();
        for record in records {
            let callable = self
                .index
                .exact_callable(record.callable().scope(), &record.callable_function())
                .ok_or_else(|| {
                    RootProgramTraversalError::Index(WorkspaceProgramIndexError::InvalidQuery {
                        reason: format!(
                            "callable evidence target {:?} is unavailable in `{}`",
                            record.callable_function(),
                            record.callable().scope()
                        ),
                    })
                })?;
            if callable.id() != *record.callable() {
                return Err(RootProgramTraversalError::Index(
                    WorkspaceProgramIndexError::InvalidQuery {
                        reason: format!(
                            "callable evidence target {:?} does not retain its exact indexed identity",
                            record.callable_function()
                        ),
                    },
                ));
            }
            let reached = ReachedCallableEvidence {
                occurrence,
                callable,
                key: record.callable_key(),
                kind: record.resolution_kind(),
                path: evidence_path,
                reach_order: self.next_evidence_order,
            };
            let key = (reached.key, reached.callable.id());
            if !self.reached_evidence_seen.insert(key) {
                continue;
            }
            self.next_evidence_order = self
                .next_evidence_order
                .checked_add(1)
                .ok_or(RootProgramTraversalError::WitnessOrderOverflow)?;
            self.reached_evidence
                .entry(reached.key)
                .or_default()
                .push(reached.clone());
            let pending = self
                .pending_invocations
                .get(&reached.key)
                .cloned()
                .unwrap_or_default();
            for invocation in pending {
                scheduled.push((invocation, reached.clone()));
            }
        }
        self.enqueue_callable_resolutions(scheduled);
        Ok(())
    }

    fn register_pending_invocation(
        &mut self,
        invocation: &PendingInvocation<'a>,
    ) -> Result<(), RootProgramTraversalError<P::Error>> {
        let scope = invocation.occurrence.reference().scope();
        let keys = self
            .index
            .callable_keys(scope, invocation.occurrence.data().key())
            .map_err(RootProgramTraversalError::Index)?
            .to_vec();
        if keys.is_empty() {
            return Ok(());
        }
        let invocation_key = (
            invocation.occurrence.id(),
            invocation.active_markers.signature(),
        );
        if !self.pending_invocation_seen.insert(invocation_key) {
            return Ok(());
        }
        let mut reached = Vec::new();
        for key in keys {
            self.pending_invocations
                .entry(key)
                .or_default()
                .push(invocation.clone());
            reached.extend(
                self.reached_evidence
                    .get(&key)
                    .into_iter()
                    .flatten()
                    .cloned(),
            );
        }
        reached.sort_unstable_by_key(|evidence| evidence.reach_order);
        self.enqueue_callable_resolutions(
            reached
                .into_iter()
                .map(|evidence| (invocation.clone(), evidence)),
        );
        Ok(())
    }

    fn enqueue_callable_resolutions(
        &mut self,
        resolutions: impl IntoIterator<Item = (PendingInvocation<'a>, ReachedCallableEvidence<'a>)>,
    ) {
        let mut scheduled = Vec::new();
        for (invocation, evidence) in resolutions {
            let dedupe = (
                invocation.occurrence.id(),
                invocation.active_markers.signature(),
                evidence.callable.id(),
            );
            if self.scheduled_resolutions.insert(dedupe) {
                scheduled.push((invocation, evidence));
            }
        }
        self.work.extend(
            scheduled
                .into_iter()
                .rev()
                .map(|(invocation, evidence)| Work::CallableResolution(invocation, evidence)),
        );
    }

    fn process_callable_resolution(
        &mut self,
        invocation: PendingInvocation<'a>,
        evidence: &ReachedCallableEvidence<'a>,
    ) -> Result<(), RootProgramTraversalError<P::Error>> {
        let edge = ProgramCompositionEdge::CallableInvocation {
            invocation: invocation.occurrence.id(),
            callable: evidence.callable.id(),
            evidence: evidence.occurrence.id().erase(),
            key: evidence.key,
            resolution: evidence.kind,
        };
        self.composition_edges.insert(edge.clone());
        let resolution_path = self.append_composition(invocation.path, edge.clone())?;
        let order = self.next_order()?;
        self.callable_resolutions.push(PreparedCallableResolution {
            order,
            edge,
            invocation_data: invocation.occurrence.data().clone(),
            evidence: evidence.occurrence.id(),
            evidence_data: evidence.occurrence.data().clone(),
            callable_data: evidence.callable.data().clone(),
            resolution_path,
            evidence_path: evidence.path,
        });
        let mut targets = self.persisted_targets(&invocation, true)?;
        targets.push(PreparedPolicyTarget {
            authority: ReconciledCallTargetAuthority::ConsumerRaw,
            role: CallTargetRole::Runtime,
            callable: evidence.callable,
            path: resolution_path,
        });
        targets.sort_by(|left, right| {
            left.role
                .cmp(&right.role)
                .then_with(|| left.callable.id().cmp(&right.callable.id()))
        });
        let effective_kind = match evidence.kind {
            CallableResolutionKind::FunctionPointerEvidence => CallKind::FnPointerCallTarget,
            CallableResolutionKind::DynamicDispatchEvidence => CallKind::DynDispatchVTableEntry,
        };
        self.process_call_policy(
            invocation,
            effective_kind,
            ProgramCallResolution::CallableEvidence {
                evidence: evidence.occurrence.id(),
                key: evidence.key,
                kind: evidence.kind,
            },
            &targets,
            resolution_path,
        )
    }

    fn follow_callable(
        &mut self,
        callable: &'a ScopedProgramEntity<CallableEntity>,
        callable_path: PreparedPathId,
        markers: PreparedMarkerState,
    ) -> Result<(), RootProgramTraversalError<P::Error>> {
        let preferred_scope = callable.reference().scope();
        let requested = *callable.data().key();
        let local = self
            .index
            .body_candidates(preferred_scope, &requested)
            .map_err(RootProgramTraversalError::Index)?;
        if let Some(candidate) = local.first().copied() {
            return self.schedule_body(callable, candidate, callable_path, markers);
        }

        let stable_crate_id = requested.definition().stable_crate_id();
        match self
            .resolver
            .resolve(preferred_scope, stable_crate_id)
            .map_err(RootProgramTraversalError::AuthorityMap)?
            .clone()
        {
            StableCrateResolution::Unmanaged => self.push_outcome(
                TraversalOutcomeKind::UnmanagedStableCrate {
                    preferred_scope: preferred_scope.clone(),
                    stable_crate_id,
                    requested,
                },
                callable_path,
            ),
            StableCrateResolution::Managed(defining_scope) => {
                let candidates = self
                    .index
                    .managed_body_candidates(&defining_scope, &requested)
                    .map_err(RootProgramTraversalError::Index)?;
                if let Some(candidate) = candidates.first().copied() {
                    self.schedule_body(callable, candidate, callable_path, markers)
                } else {
                    self.push_outcome(
                        TraversalOutcomeKind::MissingManagedBody {
                            preferred_scope: preferred_scope.clone(),
                            defining_scope,
                            stable_crate_id,
                            requested,
                        },
                        callable_path,
                    )
                }
            }
        }
    }

    fn schedule_body(
        &mut self,
        callable: &'a ScopedProgramEntity<CallableEntity>,
        candidate: super::super::workspace_index::FunctionBodyCandidate<'a>,
        callable_path: PreparedPathId,
        markers: PreparedMarkerState,
    ) -> Result<(), RootProgramTraversalError<P::Error>> {
        let selected = candidate.body();
        let edge = ProgramCompositionEdge::CallableBody {
            callable: callable.id(),
            body: selected.id(),
            selection: candidate.selection_kind(),
        };
        self.composition_edges.insert(edge.clone());
        let body_path = self.append_composition(callable_path, edge)?;
        let selected_callable = callable_for_body(self.index, selected)?;
        self.work.push(Work::Body(BodyWork {
            body: selected,
            callable: selected_callable,
            carried_markers: markers,
            path: body_path,
            is_root: false,
        }));
        Ok(())
    }

    fn occurrences_for_body(
        &mut self,
        body: &'a ScopedProgramEntity<FunctionEntity>,
        body_path: PreparedPathId,
        markers: &PreparedMarkerState,
        consumer_source: Option<&Rc<ConsumerSourcePlan<'a>>>,
    ) -> Result<Vec<OccurrenceWork<'a>>, RootProgramTraversalError<P::Error>> {
        let scope = body.reference().scope();
        let sites = self
            .index
            .call_site_edges_owned_by(scope, body.data().key())
            .map_err(RootProgramTraversalError::Index)?;
        let mut work = Vec::new();
        for site_edge in sites {
            let call_site = self
                .index
                .exact_call_site(scope, &site_edge.site())
                .ok_or_else(|| {
                    RootProgramTraversalError::Index(WorkspaceProgramIndexError::InvalidQuery {
                        reason: format!(
                            "call site {:?} is unavailable in `{scope}`",
                            site_edge.site()
                        ),
                    })
                })?;
            let occurrences = self
                .index
                .call_occurrence_edges_at(scope, &site_edge.site())
                .map_err(RootProgramTraversalError::Index)?;
            for occurrence_edge in occurrences {
                let occurrence = self
                    .index
                    .exact_call_occurrence(scope, &occurrence_edge.occurrence())
                    .ok_or_else(|| {
                        RootProgramTraversalError::Index(WorkspaceProgramIndexError::InvalidQuery {
                            reason: format!(
                                "call occurrence {:?} is unavailable in `{scope}`",
                                occurrence_edge.occurrence()
                            ),
                        })
                    })?;
                let is_callable_evidence = matches!(
                    occurrence.data().kind(),
                    CallKind::FnPointerReify
                        | CallKind::ClosureFnPointerReify
                        | CallKind::VTableEntry
                );
                let applicable = occurrence
                    .data()
                    .applicable_attribution()
                    .contains(&self.request.attribution)
                    || (self.request.attribution == CallAttributionRole::CallSite
                        && is_callable_evidence);
                if !applicable {
                    continue;
                }
                let (path, macro_frames) = self.occurrence_path(
                    body,
                    body_path,
                    call_site,
                    site_edge,
                    occurrence,
                    occurrence_edge,
                )?;
                let group_key = self
                    .index
                    .occurrence_safety_group(scope, occurrence.data().key())
                    .map_err(RootProgramTraversalError::Index)?;
                let safety_group =
                    self.index
                        .exact_safety_group(scope, group_key)
                        .ok_or_else(|| {
                            RootProgramTraversalError::Index(
                                WorkspaceProgramIndexError::InvalidQuery {
                                    reason: format!(
                                        "safety group {group_key:?} is unavailable in `{scope}`"
                                    ),
                                },
                            )
                        })?;
                let source_anchors = self
                    .index
                    .call_source_anchors(scope, occurrence.data().key())
                    .map_err(RootProgramTraversalError::Index)?
                    .iter()
                    .map(|anchor| ResolvedCallSourceAnchor {
                        role: anchor.role(),
                        key: anchor.anchor_key().clone(),
                        anchor: anchor.anchor().clone(),
                        relation: anchor.relation().clone(),
                    })
                    .collect();
                work.push(OccurrenceWork {
                    call_site,
                    occurrence,
                    safety_group,
                    source_anchors,
                    macro_frames,
                    carried_markers: markers.clone(),
                    consumer_source: consumer_source.cloned(),
                    path,
                });
            }
        }
        Ok(work)
    }

    fn effects_for_body(
        &mut self,
        body: &'a ScopedProgramEntity<FunctionEntity>,
        body_path: PreparedPathId,
        markers: &PreparedMarkerState,
    ) -> Result<Vec<EffectWork<'a>>, RootProgramTraversalError<P::Error>> {
        let scope = body.reference().scope();
        let sites = self
            .index
            .effect_site_edges_owned_by(scope, body.data().key())
            .map_err(RootProgramTraversalError::Index)?;
        let mut work = Vec::with_capacity(sites.len());
        for site in sites {
            let effect = self
                .index
                .exact_effect_site(scope, &site.site())
                .ok_or_else(|| {
                    RootProgramTraversalError::Index(WorkspaceProgramIndexError::InvalidQuery {
                        reason: format!(
                            "effect site {:?} is unavailable in `{scope}`",
                            site.site()
                        ),
                    })
                })?;
            if &effect.id() != site.effect() {
                return Err(RootProgramTraversalError::Index(
                    WorkspaceProgramIndexError::InvalidQuery {
                        reason: format!(
                            "effect site {:?} does not retain its exact indexed identity",
                            site.site()
                        ),
                    },
                ));
            }
            let source_anchors = self
                .index
                .effect_source_anchors(scope, &site.site())
                .map_err(RootProgramTraversalError::Index)?
                .iter()
                .map(|anchor| ResolvedEffectSourceAnchor {
                    role: anchor.role(),
                    key: anchor.anchor_key().clone(),
                    anchor: anchor.anchor().clone(),
                    relation: anchor.relation().clone(),
                })
                .collect();
            let (path, macro_frames) =
                self.effect_path_and_frames(body, body_path, effect, site.relation().clone())?;
            work.push(EffectWork {
                effect,
                source_anchors,
                macro_frames,
                carried_markers: markers.clone(),
                path,
            });
        }
        Ok(work)
    }

    fn unsafe_operations_for_body(
        &mut self,
        body: &'a ScopedProgramEntity<FunctionEntity>,
        body_path: PreparedPathId,
        markers: &PreparedMarkerState,
    ) -> Result<Vec<UnsafeOperationWork<'a>>, RootProgramTraversalError<P::Error>> {
        let body_id = body.id();
        let routes = if let Some(routes) = self.unsafe_operation_routes.get(&body_id) {
            #[cfg(test)]
            {
                self.consumer_reconciliation_metrics.unsafe_route_cache_hits += 1;
            }
            Rc::clone(routes)
        } else {
            let routes = Rc::new(self.index_unsafe_operation_routes(body)?);
            #[cfg(test)]
            {
                self.consumer_reconciliation_metrics
                    .unsafe_route_indexes_built += 1;
            }
            self.unsafe_operation_routes
                .insert(body_id, Rc::clone(&routes));
            routes
        };
        let mut work = Vec::with_capacity(routes.len());
        for route in routes.iter() {
            let path = self.materialize_unsafe_operation_path(body, body_path, route)?;
            work.push(UnsafeOperationWork {
                operation: route.operation,
                owner: body,
                owner_relation: route.owner_relation.clone(),
                safety_group: route.safety_group,
                safety_group_relation: route.safety_group_relation.clone(),
                source_anchors: route.source_anchors.clone(),
                macro_frames: route.macro_frames.clone(),
                carried_markers: markers.clone(),
                path,
            });
        }
        Ok(work)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one pass validates and retains each exact unsafe-operation route atomically"
    )]
    fn index_unsafe_operation_routes(
        &self,
        body: &'a ScopedProgramEntity<FunctionEntity>,
    ) -> Result<Vec<UnsafeOperationRoute<'a>>, RootProgramTraversalError<P::Error>> {
        let scope = body.reference().scope();
        let operations = self
            .index
            .unsafe_operation_edges_owned_by(scope, body.data().key())
            .map_err(RootProgramTraversalError::Index)?;
        let mut routes = Vec::with_capacity(operations.len());
        for indexed in operations {
            let operation = self
                .index
                .exact_unsafe_operation(scope, &indexed.operation())
                .ok_or_else(|| {
                    RootProgramTraversalError::Index(WorkspaceProgramIndexError::InvalidQuery {
                        reason: format!(
                            "unsafe operation {:?} is unavailable in `{scope}`",
                            indexed.operation()
                        ),
                    })
                })?;
            if &operation.id() != indexed.operation_id() {
                return Err(RootProgramTraversalError::Index(
                    WorkspaceProgramIndexError::InvalidQuery {
                        reason: format!(
                            "unsafe operation {:?} does not retain its exact indexed identity",
                            indexed.operation()
                        ),
                    },
                ));
            }
            let group_edge = self
                .index
                .unsafe_operation_group_edge(scope, &indexed.operation())
                .map_err(RootProgramTraversalError::Index)?;
            let group = self
                .index
                .exact_safety_group(scope, group_edge.group().data().key())
                .ok_or_else(|| {
                    RootProgramTraversalError::Index(WorkspaceProgramIndexError::InvalidQuery {
                        reason: format!(
                            "unsafe operation {:?} safety group is unavailable in `{scope}`",
                            indexed.operation()
                        ),
                    })
                })?;
            if group.id() != group_edge.group().id() {
                return Err(RootProgramTraversalError::Index(
                    WorkspaceProgramIndexError::InvalidQuery {
                        reason: format!(
                            "unsafe operation {:?} safety group does not retain its exact indexed identity",
                            indexed.operation()
                        ),
                    },
                ));
            }
            let source_anchors = self
                .index
                .unsafe_operation_source_anchors(scope, &indexed.operation())
                .map_err(RootProgramTraversalError::Index)?
                .iter()
                .map(|anchor| {
                    let exact = self
                        .index
                        .exact_source_anchor(scope, anchor.anchor_key())
                        .ok_or_else(|| {
                            RootProgramTraversalError::Index(
                                WorkspaceProgramIndexError::InvalidQuery {
                                    reason: format!(
                                        "unsafe operation {:?} source anchor {:?} is unavailable in `{scope}`",
                                        indexed.operation(),
                                        anchor.anchor_key()
                                    ),
                                },
                            )
                        })?;
                    if exact.id() != *anchor.anchor() {
                        return Err(RootProgramTraversalError::Index(
                            WorkspaceProgramIndexError::InvalidQuery {
                                reason: format!(
                                    "unsafe operation {:?} source anchor {:?} does not retain its exact indexed identity",
                                    indexed.operation(),
                                    anchor.anchor_key()
                                ),
                            },
                        ));
                    }
                    Ok(ResolvedUnsafeOperationSourceAnchor {
                        role: anchor.role(),
                        key: anchor.anchor_key().clone(),
                        anchor: anchor.anchor().clone(),
                        relation: anchor.relation().clone(),
                    })
                })
                .collect::<Result<Vec<_>, RootProgramTraversalError<P::Error>>>()?;
            let (path, macro_frames) =
                self.unsafe_operation_path_plan(operation, indexed.relation().clone())?;
            routes.push(UnsafeOperationRoute {
                operation,
                owner_relation: indexed.relation().clone(),
                safety_group: group,
                safety_group_relation: group_edge.relation().clone(),
                source_anchors,
                macro_frames,
                path,
            });
        }
        Ok(routes)
    }

    fn unsafe_operation_path_plan(
        &self,
        operation: &'a ScopedProgramEntity<UnsafeOperationEntity>,
        ownership: ScopedRelationRef,
    ) -> Result<
        (UnsafeOperationPath, Vec<ResolvedUnsafeOperationMacroFrame>),
        RootProgramTraversalError<P::Error>,
    > {
        let scope = operation.reference().scope();
        let Some(macro_path) = self
            .index
            .unsafe_operation_macro_path(scope, operation.data().key())
            .map_err(RootProgramTraversalError::Index)?
            .cloned()
        else {
            return Ok((UnsafeOperationPath::Direct(ownership), Vec::new()));
        };
        if macro_path.frames().is_empty()
            || macro_path.links().len() + 1 != macro_path.frames().len()
            || macro_path.callsites().len() != macro_path.frames().len()
        {
            return Err(RootProgramTraversalError::InvalidPreparedPath {
                reason: format!(
                    "indexed unsafe-operation macro path for {:?} has misaligned frames, links, or callsites",
                    operation.data().key()
                ),
            });
        }
        let mut macro_frames = Vec::with_capacity(macro_path.frames().len());
        for (frame, callsite) in macro_path.frames().iter().zip(macro_path.callsites()) {
            let exact = self
                .index
                .exact_unsafe_macro(scope, frame.data().key())
                .ok_or_else(|| {
                    RootProgramTraversalError::Index(WorkspaceProgramIndexError::InvalidQuery {
                        reason: format!(
                            "unsafe-operation macro frame {:?} is unavailable in `{scope}`",
                            frame.data().key()
                        ),
                    })
                })?;
            if exact.id() != frame.id() {
                return Err(RootProgramTraversalError::Index(
                    WorkspaceProgramIndexError::InvalidQuery {
                        reason: format!(
                            "unsafe-operation macro frame {:?} does not retain its exact indexed identity",
                            frame.data().key()
                        ),
                    },
                ));
            }
            let callsite = callsite
                .as_ref()
                .map(|callsite| {
                    let exact = self
                        .index
                        .exact_source_anchor(scope, callsite.anchor_key())
                        .ok_or_else(|| {
                            RootProgramTraversalError::Index(
                                WorkspaceProgramIndexError::InvalidQuery {
                                    reason: format!(
                                        "unsafe-operation macro callsite {:?} is unavailable in `{scope}`",
                                        callsite.anchor_key()
                                    ),
                                },
                            )
                        })?;
                    if exact.id() != *callsite.anchor() {
                        return Err(RootProgramTraversalError::Index(
                            WorkspaceProgramIndexError::InvalidQuery {
                                reason: format!(
                                    "unsafe-operation macro callsite {:?} does not retain its exact indexed identity",
                                    callsite.anchor_key()
                                ),
                            },
                        ));
                    }
                    Ok(ResolvedUnsafeOperationMacroCallsite {
                        key: callsite.anchor_key().clone(),
                        anchor: callsite.anchor().clone(),
                        relation: callsite.relation().clone(),
                    })
                })
                .transpose()?;
            macro_frames.push(ResolvedUnsafeOperationMacroFrame {
                frame: frame.id(),
                data: frame.data().clone(),
                callsite,
            });
        }
        Ok((
            UnsafeOperationPath::Macro {
                entry: macro_path.entry().clone(),
                links: macro_path.links().to_vec(),
                exit: macro_path.exit().clone(),
                frame_ids: macro_path
                    .frames()
                    .iter()
                    .map(|frame| frame.id().erase())
                    .collect(),
            },
            macro_frames,
        ))
    }

    fn materialize_unsafe_operation_path(
        &mut self,
        body: &'a ScopedProgramEntity<FunctionEntity>,
        body_path: PreparedPathId,
        route: &UnsafeOperationRoute<'a>,
    ) -> Result<PreparedPathId, RootProgramTraversalError<P::Error>> {
        match &route.path {
            UnsafeOperationPath::Direct(ownership) => self.append_artifact(
                body_path,
                &body.id().erase(),
                route.operation.id().erase(),
                ownership.clone(),
            ),
            UnsafeOperationPath::Macro {
                entry,
                links,
                exit,
                frame_ids,
            } => {
                if !validate_unsafe_operation_path_shape(frame_ids.len(), links.len()) {
                    return Err(RootProgramTraversalError::InvalidPreparedPath {
                        reason: format!(
                            "cached unsafe-operation macro path for {:?} has misaligned frames and links",
                            route.operation.data().key()
                        ),
                    });
                }
                let (first, remaining) = frame_ids.split_first().ok_or_else(|| {
                    RootProgramTraversalError::InvalidPreparedPath {
                        reason: format!(
                            "cached unsafe-operation macro path for {:?} has no frames",
                            route.operation.data().key()
                        ),
                    }
                })?;
                let mut path = self.append_artifact(
                    body_path,
                    &body.id().erase(),
                    first.clone(),
                    entry.clone(),
                )?;
                for (pair, relation) in frame_ids.windows(2).zip(links) {
                    path =
                        self.append_artifact(path, &pair[0], pair[1].clone(), relation.clone())?;
                }
                let final_frame = match remaining.last() {
                    Some(frame) => frame,
                    None => first,
                };
                self.append_artifact(
                    path,
                    final_frame,
                    route.operation.id().erase(),
                    exit.clone(),
                )
            }
        }
    }

    fn effect_path_and_frames(
        &mut self,
        body: &'a ScopedProgramEntity<FunctionEntity>,
        body_path: PreparedPathId,
        effect: &'a ScopedProgramEntity<EffectSiteEntity>,
        ownership: ScopedRelationRef,
    ) -> Result<(PreparedPathId, Vec<ResolvedEffectMacroFrame>), RootProgramTraversalError<P::Error>>
    {
        let scope = effect.reference().scope();
        let Some(macro_path) = self
            .index
            .effect_macro_path(scope, effect.data().site())
            .map_err(RootProgramTraversalError::Index)?
            .cloned()
        else {
            let path = self.append_artifact(
                body_path,
                &body.id().erase(),
                effect.id().erase(),
                ownership,
            )?;
            return Ok((path, Vec::new()));
        };
        if macro_path.frames().is_empty()
            || macro_path.links().len() + 1 != macro_path.frames().len()
            || macro_path.callsites().len() != macro_path.frames().len()
        {
            return Err(RootProgramTraversalError::InvalidPreparedPath {
                reason: format!(
                    "indexed effect macro path for {:?} has misaligned frames, links, or callsites",
                    effect.data().site()
                ),
            });
        }
        let macro_frames = macro_path
            .frames()
            .iter()
            .zip(macro_path.callsites())
            .map(|(frame, callsite)| ResolvedEffectMacroFrame {
                frame: frame.id(),
                data: frame.data().clone(),
                callsite: callsite
                    .as_ref()
                    .map(|callsite| ResolvedEffectMacroCallsite {
                        key: callsite.anchor_key().clone(),
                        anchor: callsite.anchor().clone(),
                        relation: callsite.relation().clone(),
                    }),
            })
            .collect();
        let first = &macro_path.frames()[0];
        let mut path = self.append_artifact(
            body_path,
            &body.id().erase(),
            first.id().erase(),
            macro_path.entry().clone(),
        )?;
        let mut previous = first;
        for (frame, relation) in macro_path.frames()[1..].iter().zip(macro_path.links()) {
            path = self.append_artifact(
                path,
                &previous.id().erase(),
                frame.id().erase(),
                relation.clone(),
            )?;
            previous = frame;
        }
        path = self.append_artifact(
            path,
            &previous.id().erase(),
            effect.id().erase(),
            macro_path.exit().clone(),
        )?;
        Ok((path, macro_frames))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the exact indexed call route is one atomic path"
    )]
    fn occurrence_path(
        &mut self,
        body: &'a ScopedProgramEntity<FunctionEntity>,
        body_path: PreparedPathId,
        call_site: &'a ScopedProgramEntity<CallSiteEntity>,
        site_edge: &super::super::workspace_index::IndexedCallSite,
        occurrence: &'a ScopedProgramEntity<CallOccurrenceEntity>,
        occurrence_edge: &super::super::workspace_index::IndexedCallOccurrence,
    ) -> Result<(PreparedPathId, Vec<ResolvedCallMacroFrame>), RootProgramTraversalError<P::Error>>
    {
        let scope = occurrence.reference().scope();
        if let Some(macro_path) = self
            .index
            .call_macro_path(scope, occurrence.data().key())
            .map_err(RootProgramTraversalError::Index)?
            .cloned()
        {
            if macro_path.frames().is_empty()
                || macro_path.links().len() + 1 != macro_path.frames().len()
                || macro_path.callsites().len() != macro_path.frames().len()
            {
                return Err(RootProgramTraversalError::InvalidPreparedPath {
                    reason: format!(
                        "indexed call macro path for {:?} has misaligned frames, links, or callsites",
                        occurrence.data().key()
                    ),
                });
            }
            let macro_frames = macro_path
                .frames()
                .iter()
                .zip(macro_path.callsites())
                .map(|(frame, callsite)| ResolvedCallMacroFrame {
                    frame: frame.id(),
                    data: frame.data().clone(),
                    callsite: callsite.as_ref().map(|callsite| ResolvedCallMacroCallsite {
                        key: callsite.anchor_key().clone(),
                        anchor: callsite.anchor().clone(),
                        relation: callsite.relation().clone(),
                    }),
                })
                .collect();
            let first = &macro_path.frames()[0];
            let mut path = self.append_artifact(
                body_path,
                &body.id().erase(),
                first.id().erase(),
                macro_path.entry().clone(),
            )?;
            let mut previous = first;
            for (frame, relation) in macro_path.frames()[1..].iter().zip(macro_path.links()) {
                path = self.append_artifact(
                    path,
                    &previous.id().erase(),
                    frame.id().erase(),
                    relation.clone(),
                )?;
                previous = frame;
            }
            let path = self.append_artifact(
                path,
                &previous.id().erase(),
                occurrence.id().erase(),
                macro_path.exit().clone(),
            )?;
            Ok((path, macro_frames))
        } else {
            let site_path = self.append_artifact(
                body_path,
                &body.id().erase(),
                call_site.id().erase(),
                site_edge.relation().clone(),
            )?;
            let path = self.append_artifact(
                site_path,
                &call_site.id().erase(),
                occurrence.id().erase(),
                occurrence_edge.relation().clone(),
            )?;
            Ok((path, Vec::new()))
        }
    }

    fn function_marker_candidates(
        &mut self,
        body: &'a ScopedProgramEntity<FunctionEntity>,
        body_path: PreparedPathId,
    ) -> Result<PreparedMarkerState, RootProgramTraversalError<P::Error>> {
        let candidates = self
            .index
            .function_marker_candidates(body.reference().scope(), body.data().key())
            .map_err(RootProgramTraversalError::Index)?
            .to_vec();
        self.activate_marker_candidates(body.reference(), body_path, &candidates)
    }

    fn call_marker_candidates(
        &mut self,
        occurrence: &'a ScopedProgramEntity<CallOccurrenceEntity>,
        occurrence_path: PreparedPathId,
    ) -> Result<PreparedMarkerState, RootProgramTraversalError<P::Error>> {
        let candidates = self
            .index
            .call_marker_candidates(occurrence.reference().scope(), occurrence.data().key())
            .map_err(RootProgramTraversalError::Index)?
            .to_vec();
        self.activate_marker_candidates(occurrence.reference(), occurrence_path, &candidates)
    }

    fn effect_marker_candidates(
        &mut self,
        effect: &'a ScopedProgramEntity<EffectSiteEntity>,
        effect_path: PreparedPathId,
    ) -> Result<PreparedMarkerState, RootProgramTraversalError<P::Error>> {
        let candidates = self
            .index
            .effect_marker_candidates(effect.reference().scope(), effect.data().site())
            .map_err(RootProgramTraversalError::Index)?
            .to_vec();
        self.activate_marker_candidates(effect.reference(), effect_path, &candidates)
    }

    fn unsafe_operation_marker_candidates(
        &mut self,
        operation: &'a ScopedProgramEntity<UnsafeOperationEntity>,
        operation_path: PreparedPathId,
    ) -> Result<PreparedMarkerState, RootProgramTraversalError<P::Error>> {
        let candidates = self
            .index
            .unsafe_marker_candidates(operation.reference().scope(), operation.data().key())
            .map_err(RootProgramTraversalError::Index)?
            .to_vec();
        self.activate_marker_candidates(operation.reference(), operation_path, &candidates)
    }

    fn activate_marker_candidates(
        &mut self,
        endpoint: &ScopedEntityRef,
        endpoint_path: PreparedPathId,
        candidates: &[super::super::workspace_index::IndexedMarkerCandidate],
    ) -> Result<PreparedMarkerState, RootProgramTraversalError<P::Error>> {
        let mut activated = PreparedMarkerState::default();
        for candidate in candidates {
            if !self.marker_is_relevant(candidate) {
                continue;
            }
            let claim = self
                .index
                .exact_marker_claim(endpoint.scope(), candidate.claim())
                .ok_or_else(|| {
                    RootProgramTraversalError::Index(WorkspaceProgramIndexError::InvalidQuery {
                        reason: format!(
                            "marker candidate claim {:?} is unavailable in `{}`",
                            candidate.claim(),
                            endpoint.scope()
                        ),
                    })
                })?;
            if &claim.id() != candidate.claim_id() {
                return Err(RootProgramTraversalError::Index(
                    WorkspaceProgramIndexError::InvalidQuery {
                        reason: format!(
                            "marker candidate claim {:?} does not retain its exact indexed identity",
                            candidate.claim()
                        ),
                    },
                ));
            }
            let claim_id = claim.id();
            let claim_data = claim.data().clone();
            let path = self.append_artifact(
                endpoint_path,
                endpoint,
                claim_id.erase(),
                candidate.relation().clone(),
            )?;
            activated.0.entry(claim_id).or_insert(PreparedMarkerClaim {
                data: claim_data,
                path,
            });
        }
        Ok(activated)
    }

    fn marker_is_relevant(
        &self,
        candidate: &super::super::workspace_index::IndexedMarkerCandidate,
    ) -> bool {
        let selected_by_probe = match self.request.marker_probe {
            MarkerProbe::SourceCallsite => candidate.source_callsite(),
            MarkerProbe::MacroDefinitionFirst => candidate.macro_definition_first(),
        };
        selected_by_probe && candidate.claim().domain() == &self.request.domain
    }

    fn prepare_consumer_reconciliations(
        &mut self,
        consumer: &OccurrenceWork<'a>,
    ) -> Result<Option<PreparedCallReconciliation<'a>>, RootProgramTraversalError<P::Error>> {
        let Some(source) = &consumer.consumer_source else {
            return Ok(None);
        };
        let Some(source_bucket) = defining_source_bucket(source, consumer) else {
            return Ok(None);
        };
        #[cfg(test)]
        {
            self.consumer_reconciliation_metrics.source_bucket_lookups += 1;
        }
        let (kind, routes) = self.select_reconciliation_routes(consumer, source_bucket)?;
        if routes.is_empty() {
            return Ok(None);
        }
        let selected = self.prepare_selected_reconciliation(consumer, kind, routes)?;
        let accepted_markers = self.accepted_defining_markers(consumer, &selected)?;
        let authorities = self.prepare_reconciliation_authorities(&selected)?;
        Ok(Some(PreparedCallReconciliation {
            candidates: selected.candidates,
            accepted_markers,
            defining_source_target: authorities.defining_source_target,
            defining_target: authorities.defining_target,
        }))
    }

    fn select_reconciliation_routes<'r>(
        &mut self,
        consumer: &OccurrenceWork<'a>,
        source_bucket: &'r DefiningSourceBucket<'a>,
    ) -> Result<
        (
            ConsumerOccurrenceReconciliationKind,
            Vec<&'r DefiningOccurrenceRoute<'a>>,
        ),
        RootProgramTraversalError<P::Error>,
    > {
        let consumer_targets = self
            .index
            .call_targets(
                consumer.occurrence.reference().scope(),
                consumer.occurrence.data().key(),
            )
            .map_err(RootProgramTraversalError::Index)?;
        let by_definition = effective_raw_target(consumer_targets).and_then(|target| {
            source_bucket
                .by_effective_definition
                .get(&target.definition())
        });
        if let Some(routes) = by_definition {
            #[cfg(test)]
            {
                self.consumer_reconciliation_metrics
                    .semantic_candidates_inspected += routes.len();
            }
            return Ok((
                ConsumerOccurrenceReconciliationKind::SemanticTarget,
                routes.iter().collect(),
            ));
        }
        let shape = semantic_shape_key(consumer.occurrence.data(), consumer_targets);
        if let Some(routes) = source_bucket.by_complete_shape.get(&shape) {
            #[cfg(test)]
            {
                self.consumer_reconciliation_metrics
                    .semantic_candidates_inspected += routes.len();
            }
            return Ok((
                ConsumerOccurrenceReconciliationKind::SemanticTarget,
                routes.iter().collect(),
            ));
        }
        Ok(if is_actual_call(consumer.occurrence.data().kind()) {
            (
                ConsumerOccurrenceReconciliationKind::SourceFallback,
                source_bucket.actual_calls.iter().collect(),
            )
        } else {
            (
                ConsumerOccurrenceReconciliationKind::SourceFallback,
                Vec::new(),
            )
        })
    }

    fn prepare_selected_reconciliation<'r>(
        &mut self,
        consumer: &OccurrenceWork<'a>,
        kind: ConsumerOccurrenceReconciliationKind,
        routes: Vec<&'r DefiningOccurrenceRoute<'a>>,
    ) -> Result<PreparedSelectedReconciliation<'r, 'a>, RootProgramTraversalError<P::Error>> {
        let mut candidates = Vec::with_capacity(routes.len());
        let mut marker_states = Vec::with_capacity(routes.len());
        let mut paths = Vec::with_capacity(routes.len());
        for candidate in &routes {
            let edge = ProgramCompositionEdge::ConsumerOccurrence {
                consumer: consumer.occurrence.id(),
                defining: candidate.occurrence.id(),
                reconciliation: kind,
            };
            self.composition_edges.insert(edge.clone());
            let path = self.append_composition(consumer.path, edge)?;
            let order = self.next_order()?;
            self.consumer_reconciliations
                .push(PreparedConsumerOccurrenceReconciliation {
                    order,
                    consumer: consumer.occurrence.id(),
                    consumer_data: consumer.occurrence.data().clone(),
                    consumer_call_site: consumer.call_site.id(),
                    consumer_call_site_data: consumer.call_site.data().clone(),
                    consumer_safety_group: consumer.safety_group.id(),
                    consumer_safety_group_data: consumer.safety_group.data().clone(),
                    defining: candidate.occurrence.id(),
                    defining_data: candidate.occurrence.data().clone(),
                    defining_call_site: candidate.call_site.id(),
                    defining_call_site_data: candidate.call_site.data().clone(),
                    defining_safety_group: candidate.safety_group.id(),
                    defining_safety_group_data: candidate.safety_group.data().clone(),
                    kind,
                    path,
                });
            let (policy_candidate, marker_state) =
                self.defining_marker_candidate(candidate, kind, path)?;
            candidates.push(policy_candidate);
            marker_states.push(marker_state);
            paths.push(path);
        }
        Ok(PreparedSelectedReconciliation {
            routes,
            paths,
            candidates,
            marker_states,
        })
    }

    fn accepted_defining_markers(
        &mut self,
        consumer: &OccurrenceWork<'a>,
        selected: &PreparedSelectedReconciliation<'_, 'a>,
    ) -> Result<PreparedMarkerState, RootProgramTraversalError<P::Error>> {
        let marker_decision = self
            .policy
            .defining_markers(&DefiningMarkerPolicyContext {
                consumer: consumer.occurrence,
                candidates: &selected.candidates,
            })
            .map_err(|source| RootProgramTraversalError::Policy {
                stage: "defining marker decision",
                source,
            })?;
        let mut accepted_markers = PreparedMarkerState::default();
        if marker_decision == DefiningMarkerDecision::UseCompleteSet {
            for markers in &selected.marker_states {
                accepted_markers.add_new(markers);
            }
        }
        Ok(accepted_markers)
    }

    fn prepare_reconciliation_authorities(
        &mut self,
        selected: &PreparedSelectedReconciliation<'_, 'a>,
    ) -> Result<PreparedReconciliationAuthorities<'a>, RootProgramTraversalError<P::Error>> {
        let defining_source_target = shared_route_target(
            &selected.routes,
            &selected.paths,
            CallTargetRole::SourceContract,
        )
        .map(|(route, path, target)| {
            self.reconciled_policy_target(
                route.occurrence,
                path,
                target,
                ReconciledCallTargetAuthority::DefiningSource,
            )
        })
        .transpose()?;
        let defining_target = shared_effective_raw_route_target(&selected.routes, &selected.paths)
            .map(|(route, path, target)| {
                self.reconciled_policy_target(
                    route.occurrence,
                    path,
                    target,
                    ReconciledCallTargetAuthority::DefiningTarget,
                )
            })
            .transpose()?;
        Ok(PreparedReconciliationAuthorities {
            defining_source_target,
            defining_target,
        })
    }

    fn defining_marker_candidate(
        &mut self,
        route: &DefiningOccurrenceRoute<'a>,
        reconciliation_kind: ConsumerOccurrenceReconciliationKind,
        reconciliation_path: PreparedPathId,
    ) -> Result<(DefiningMarkerCandidate, PreparedMarkerState), RootProgramTraversalError<P::Error>>
    {
        let indexed_markers = self
            .index
            .call_marker_candidates(
                route.occurrence.reference().scope(),
                route.occurrence.data().key(),
            )
            .map_err(RootProgramTraversalError::Index)?
            .to_vec();
        let marker_state = self.activate_marker_candidates(
            route.occurrence.reference(),
            reconciliation_path,
            &indexed_markers,
        )?;
        let expanded = resolved_anchor(
            self.index,
            route.occurrence.reference().scope(),
            &route.source_anchors,
            CallSourceAnchorRole::Expanded,
        )?
        .ok_or_else(|| RootProgramTraversalError::InvalidPreparedPath {
            reason: format!(
                "selected defining occurrence {:?} has no expanded source anchor",
                route.occurrence.data().key()
            ),
        })?;
        let callee = resolved_anchor(
            self.index,
            route.occurrence.reference().scope(),
            &route.source_anchors,
            CallSourceAnchorRole::Callee,
        )?;
        Ok((
            DefiningMarkerCandidate {
                occurrence: route.occurrence.id(),
                data: route.occurrence.data().clone(),
                call_site: route.call_site.id(),
                call_site_data: route.call_site.data().clone(),
                safety_group: route.safety_group.id(),
                safety_group_data: route.safety_group.data().clone(),
                reconciliation_kind,
                expanded_anchor: expanded.id(),
                expanded_anchor_data: expanded.data().clone(),
                callee_anchor: callee.map(ScopedProgramEntity::id),
                callee_anchor_data: callee.map(|anchor| anchor.data().clone()),
                marker_claims: marker_state.policy_values(),
            },
            marker_state,
        ))
    }

    fn reconciled_policy_target(
        &mut self,
        occurrence: &ScopedProgramEntity<CallOccurrenceEntity>,
        reconciliation_path: PreparedPathId,
        target: &DefiningTargetRoute<'a>,
        authority: ReconciledCallTargetAuthority,
    ) -> Result<PreparedPolicyTarget<'a>, RootProgramTraversalError<P::Error>> {
        let path = self.append_artifact(
            reconciliation_path,
            &occurrence.id().erase(),
            target.callable.id().erase(),
            target.relation.clone(),
        )?;
        Ok(PreparedPolicyTarget {
            authority,
            role: target.role,
            callable: target.callable,
            path,
        })
    }

    fn index_defining_occurrence_routes(
        &mut self,
        defining: &'a ScopedProgramEntity<FunctionEntity>,
    ) -> Result<
        BTreeMap<DefiningSourceKey, DefiningSourceBucket<'a>>,
        RootProgramTraversalError<P::Error>,
    > {
        let scope = defining.reference().scope();
        let sites = self
            .index
            .call_site_edges_owned_by(scope, defining.data().key())
            .map_err(RootProgramTraversalError::Index)?;
        let mut buckets = BTreeMap::<DefiningSourceKey, DefiningSourceBucket<'a>>::new();
        for site_edge in sites {
            let call_site = self
                .index
                .exact_call_site(scope, &site_edge.site())
                .ok_or_else(|| {
                    RootProgramTraversalError::Index(WorkspaceProgramIndexError::InvalidQuery {
                        reason: format!(
                            "defining call site {:?} is unavailable in `{scope}`",
                            site_edge.site()
                        ),
                    })
                })?;
            let occurrences = self
                .index
                .call_occurrence_edges_at(scope, &site_edge.site())
                .map_err(RootProgramTraversalError::Index)?;
            for occurrence_edge in occurrences {
                let occurrence = self
                    .index
                    .exact_call_occurrence(scope, &occurrence_edge.occurrence())
                    .ok_or_else(|| {
                        RootProgramTraversalError::Index(WorkspaceProgramIndexError::InvalidQuery {
                            reason: format!(
                                "defining call occurrence {:?} is unavailable in `{scope}`",
                                occurrence_edge.occurrence()
                            ),
                        })
                    })?;
                if !occurrence
                    .data()
                    .applicable_attribution()
                    .contains(&self.request.attribution)
                {
                    continue;
                }
                let source_anchors = self
                    .index
                    .call_source_anchors(scope, occurrence.data().key())
                    .map_err(RootProgramTraversalError::Index)?
                    .iter()
                    .map(|anchor| ResolvedCallSourceAnchor {
                        role: anchor.role(),
                        key: anchor.anchor_key().clone(),
                        anchor: anchor.anchor().clone(),
                        relation: anchor.relation().clone(),
                    })
                    .collect::<Vec<_>>();
                let Some(expanded) =
                    call_anchor_key(&source_anchors, CallSourceAnchorRole::Expanded).cloned()
                else {
                    continue;
                };
                let callee =
                    call_anchor_key(&source_anchors, CallSourceAnchorRole::Callee).cloned();
                let group_key = self
                    .index
                    .occurrence_safety_group(scope, occurrence.data().key())
                    .map_err(RootProgramTraversalError::Index)?;
                let safety_group = self.index.exact_safety_group(scope, group_key).ok_or_else(
                    || {
                        RootProgramTraversalError::Index(WorkspaceProgramIndexError::InvalidQuery {
                            reason: format!(
                                "defining safety group {group_key:?} is unavailable in `{scope}`"
                            ),
                        })
                    },
                )?;
                let route = DefiningOccurrenceRoute {
                    call_site,
                    occurrence,
                    safety_group,
                    source_anchors,
                    targets: defining_target_routes(self.index, occurrence)
                        .map_err(RootProgramTraversalError::Index)?,
                };
                #[cfg(test)]
                {
                    self.consumer_reconciliation_metrics.defining_routes_indexed += 1;
                }
                index_defining_route(buckets.entry((expanded, callee)).or_default(), route);
            }
        }
        Ok(buckets)
    }

    fn prepare_consumer_source(
        &mut self,
        consumer: &'a ScopedProgramEntity<FunctionEntity>,
        consumer_path: PreparedPathId,
    ) -> Result<Option<PreparedConsumerSource<'a>>, RootProgramTraversalError<P::Error>> {
        if !matches!(
            consumer.data().provenance(),
            super::super::FunctionBodyProvenance::ConsumerInstantiation { .. }
        ) {
            return Ok(None);
        }
        let preferred_scope = consumer.reference().scope();
        let stable_crate_id = consumer.data().key().definition().stable_crate_id();
        match self
            .resolver
            .resolve(preferred_scope, stable_crate_id)
            .map_err(RootProgramTraversalError::AuthorityMap)?
            .clone()
        {
            StableCrateResolution::Unmanaged => {
                self.push_outcome(
                    TraversalOutcomeKind::UnmanagedDefiningSource {
                        preferred_scope: preferred_scope.clone(),
                        stable_crate_id,
                        consumer: *consumer.data().key(),
                    },
                    consumer_path,
                )?;
                Ok(None)
            }
            StableCrateResolution::Managed(defining_scope) => {
                let candidates = self
                    .index
                    .defining_body_candidates(
                        preferred_scope,
                        consumer.data().key(),
                        &defining_scope,
                    )
                    .map_err(RootProgramTraversalError::Index)?;
                let Some(candidate) = candidates.first().copied() else {
                    self.push_outcome(
                        TraversalOutcomeKind::MissingManagedDefiningSource {
                            preferred_scope: preferred_scope.clone(),
                            defining_scope,
                            stable_crate_id,
                            consumer: *consumer.data().key(),
                        },
                        consumer_path,
                    )?;
                    return Ok(None);
                };
                let defining = candidate.body();
                let edge = ProgramCompositionEdge::ConsumerBody {
                    consumer: consumer.id(),
                    defining: defining.id(),
                };
                self.composition_edges.insert(edge.clone());
                let path = self.append_composition(consumer_path, edge)?;
                let order = self.next_order()?;
                self.consumer_body_sources.push(PreparedConsumerBodySource {
                    order,
                    consumer: consumer.id(),
                    consumer_data: consumer.data().clone(),
                    defining: defining.id(),
                    defining_data: defining.data().clone(),
                    selection: candidate.selection_kind(),
                    path,
                });
                let plan_key = (consumer.id(), defining.id());
                if let Some(plan) = self.consumer_source_plans.get(&plan_key) {
                    #[cfg(test)]
                    {
                        self.consumer_reconciliation_metrics.plan_cache_hits += 1;
                    }
                    return Ok(Some(PreparedConsumerSource {
                        plan: Rc::clone(plan),
                        defining_body: defining,
                        defining_path: path,
                    }));
                }
                let buckets_by_source = self.index_defining_occurrence_routes(defining)?;
                #[cfg(test)]
                {
                    self.consumer_reconciliation_metrics.plans_built += 1;
                }
                let plan = Rc::new(ConsumerSourcePlan { buckets_by_source });
                self.consumer_source_plans
                    .insert(plan_key, Rc::clone(&plan));
                Ok(Some(PreparedConsumerSource {
                    plan,
                    defining_body: defining,
                    defining_path: path,
                }))
            }
        }
    }

    fn push_outcome(
        &mut self,
        kind: TraversalOutcomeKind,
        path: PreparedPathId,
    ) -> Result<(), RootProgramTraversalError<P::Error>> {
        let order = self.next_order()?;
        self.outcomes
            .push(PreparedTraversalOutcome { order, kind, path });
        Ok(())
    }

    fn next_order(&mut self) -> Result<u64, RootProgramTraversalError<P::Error>> {
        next_witness_order(&mut self.order)
    }

    fn append_artifact(
        &mut self,
        path: PreparedPathId,
        from: &ScopedEntityRef,
        to: ScopedEntityRef,
        relation: ScopedRelationRef,
    ) -> Result<PreparedPathId, RootProgramTraversalError<P::Error>> {
        self.paths
            .append_artifact(path, from, to, relation)
            .map_err(|reason| RootProgramTraversalError::InvalidPreparedPath { reason })
    }

    fn append_composition(
        &mut self,
        path: PreparedPathId,
        edge: ProgramCompositionEdge,
    ) -> Result<PreparedPathId, RootProgramTraversalError<P::Error>> {
        self.paths
            .append_composition(path, edge)
            .map_err(|reason| RootProgramTraversalError::InvalidPreparedPath { reason })
    }
}

fn call_anchor_key(
    anchors: &[ResolvedCallSourceAnchor],
    role: CallSourceAnchorRole,
) -> Option<&SourceAnchorKey> {
    anchors
        .iter()
        .find(|anchor| anchor.role() == role)
        .map(ResolvedCallSourceAnchor::key)
}

fn defining_source_bucket<'r, 'a>(
    source: &'r ConsumerSourcePlan<'a>,
    consumer: &OccurrenceWork<'a>,
) -> Option<&'r DefiningSourceBucket<'a>> {
    let consumer_expanded =
        call_anchor_key(&consumer.source_anchors, CallSourceAnchorRole::Expanded)?;
    let consumer_callee = call_anchor_key(&consumer.source_anchors, CallSourceAnchorRole::Callee);
    source
        .buckets_by_source
        .get(&(consumer_expanded.clone(), consumer_callee.cloned()))
}

fn index_defining_route<'a>(
    bucket: &mut DefiningSourceBucket<'a>,
    route: DefiningOccurrenceRoute<'a>,
) {
    let raw_targets = route
        .targets
        .iter()
        .filter(|target| is_raw_target_role(target.role))
        .map(|target| (target.role, target.callable.data().key().definition()))
        .collect::<RawTargetShape>();
    let shape = SemanticShapeKey {
        kind: route.occurrence.data().kind(),
        raw_targets,
        opaque_description: route
            .occurrence
            .data()
            .opaque_target_description()
            .map(str::to_owned),
    };
    bucket
        .by_complete_shape
        .entry(shape)
        .or_default()
        .push(route.clone());
    if let Some(target) = effective_defining_raw_target(&route.targets) {
        bucket
            .by_effective_definition
            .entry(target.callable.data().key().definition())
            .or_default()
            .push(route.clone());
    }
    if is_actual_call(route.occurrence.data().kind()) {
        bucket.actual_calls.push(route);
    }
}

fn resolved_anchor<'a, E: Error>(
    index: &'a WorkspaceProgramIndex,
    scope: &ArtifactScopeId,
    anchors: &[ResolvedCallSourceAnchor],
    role: CallSourceAnchorRole,
) -> Result<Option<&'a ScopedProgramEntity<SourceAnchorEntity>>, RootProgramTraversalError<E>> {
    let Some(anchor) = anchors.iter().find(|anchor| anchor.role() == role) else {
        return Ok(None);
    };
    let entity = index
        .exact_source_anchor(scope, anchor.key())
        .ok_or_else(|| {
            RootProgramTraversalError::Index(WorkspaceProgramIndexError::InvalidQuery {
                reason: format!(
                    "{role:?} source anchor {:?} is unavailable in `{scope}`",
                    anchor.key()
                ),
            })
        })?;
    if entity.id() != *anchor.anchor() {
        return Err(RootProgramTraversalError::Index(
            WorkspaceProgramIndexError::InvalidQuery {
                reason: format!(
                    "{role:?} source anchor {:?} does not retain its exact indexed identity",
                    anchor.key()
                ),
            },
        ));
    }
    Ok(Some(entity))
}

fn defining_target_routes<'a>(
    index: &'a WorkspaceProgramIndex,
    occurrence: &'a ScopedProgramEntity<CallOccurrenceEntity>,
) -> Result<Vec<DefiningTargetRoute<'a>>, WorkspaceProgramIndexError> {
    let scope = occurrence.reference().scope();
    index
        .call_targets(scope, occurrence.data().key())?
        .iter()
        .map(|target| {
            let callable = index
                .exact_callable(scope, &target.callable())
                .ok_or_else(|| WorkspaceProgramIndexError::InvalidQuery {
                    reason: format!(
                        "defining call target {:?} is unavailable in `{scope}`",
                        target.callable()
                    ),
                })?;
            Ok(DefiningTargetRoute {
                role: target.role(),
                callable,
                relation: target.relation().clone(),
            })
        })
        .collect()
}

fn shared_route_target<'a, 'b>(
    routes: &'b [&'b DefiningOccurrenceRoute<'a>],
    paths: &'b [PreparedPathId],
    role: CallTargetRole,
) -> Option<(
    &'b DefiningOccurrenceRoute<'a>,
    PreparedPathId,
    &'b DefiningTargetRoute<'a>,
)> {
    let first_route = *routes.first()?;
    let first_target = first_route
        .targets
        .iter()
        .find(|target| target.role == role)?;
    routes
        .iter()
        .skip(1)
        .all(|route| {
            route
                .targets
                .iter()
                .find(|target| target.role == role)
                .is_some_and(|target| target.callable.id() == first_target.callable.id())
        })
        .then(|| (first_route, paths[0], first_target))
}

fn shared_effective_raw_route_target<'a, 'b>(
    routes: &'b [&'b DefiningOccurrenceRoute<'a>],
    paths: &'b [PreparedPathId],
) -> Option<(
    &'b DefiningOccurrenceRoute<'a>,
    PreparedPathId,
    &'b DefiningTargetRoute<'a>,
)> {
    let first_route = *routes.first()?;
    let first_target = effective_defining_raw_target(&first_route.targets)?;
    routes
        .iter()
        .skip(1)
        .all(|route| {
            effective_defining_raw_target(&route.targets).is_some_and(|target| {
                target.role == first_target.role
                    && target.callable.id() == first_target.callable.id()
            })
        })
        .then(|| (first_route, paths[0], first_target))
}

fn effective_defining_raw_target<'a, 'b>(
    targets: &'b [DefiningTargetRoute<'a>],
) -> Option<&'b DefiningTargetRoute<'a>> {
    targets
        .iter()
        .find(|target| target.role == CallTargetRole::Runtime)
        .or_else(|| {
            targets.iter().find(|target| {
                matches!(
                    target.role,
                    CallTargetRole::OpaqueTrait | CallTargetRole::OpaqueFunction
                )
            })
        })
}

fn effective_prepared_raw_target<'a, 'b>(
    targets: &'b [PreparedPolicyTarget<'a>],
) -> Option<&'b PreparedPolicyTarget<'a>> {
    targets
        .iter()
        .find(|target| target.role == CallTargetRole::Runtime)
        .or_else(|| {
            targets.iter().find(|target| {
                matches!(
                    target.role,
                    CallTargetRole::OpaqueTrait | CallTargetRole::OpaqueFunction
                )
            })
        })
}

fn policy_reconciliation_target<'a>(
    target: &PreparedPolicyTarget<'a>,
) -> ReconciledCallTargetPolicyCandidate<'a> {
    ReconciledCallTargetPolicyCandidate {
        authority: target.authority,
        role: target.role,
        callable: target.callable,
    }
}

fn policy_reconciliation_context<'facts, 'context>(
    reconciliation: Option<&'context PreparedCallReconciliation<'facts>>,
    targets: &'context [PreparedPolicyTarget<'facts>],
    selectable_targets: &mut Vec<PreparedPolicyTarget<'facts>>,
) -> Option<CallReconciliationContext<'context>>
where
    'facts: 'context,
{
    let reconciliation = reconciliation?;
    let raw_target = effective_prepared_raw_target(targets).map(policy_reconciliation_target);
    let consumer_source = targets
        .iter()
        .find(|target| target.role == CallTargetRole::SourceContract)
        .map(|target| PreparedPolicyTarget {
            authority: ReconciledCallTargetAuthority::ConsumerSource,
            role: target.role,
            callable: target.callable,
            path: target.path,
        });
    selectable_targets.extend(consumer_source.iter().cloned());
    selectable_targets.extend(reconciliation.defining_source_target.iter().cloned());
    selectable_targets.extend(reconciliation.defining_target.iter().cloned());

    let defining_source_target = reconciliation
        .defining_source_target
        .as_ref()
        .map(policy_reconciliation_target);
    let effective_source_target = reconciliation
        .defining_source_target
        .as_ref()
        .map(policy_reconciliation_target)
        .or_else(|| consumer_source.as_ref().map(policy_reconciliation_target));
    let defining_target = reconciliation
        .defining_target
        .as_ref()
        .map(policy_reconciliation_target);
    let effective_metadata_targets = [raw_target, defining_target, effective_source_target]
        .into_iter()
        .flatten()
        .collect();
    let contract_targets = [effective_source_target, raw_target.or(defining_target)]
        .into_iter()
        .flatten()
        .collect();
    Some(CallReconciliationContext {
        candidates: &reconciliation.candidates,
        raw_target,
        defining_source_target,
        effective_source_target,
        defining_target,
        effective_metadata_targets,
        contract_targets,
    })
}

const fn is_actual_call(kind: CallKind) -> bool {
    matches!(
        kind,
        CallKind::DirectCall
            | CallKind::TailCall
            | CallKind::IndirectCall
            | CallKind::FnPointerCallTarget
            | CallKind::DynDispatchVTableEntry
    )
}

fn effective_raw_target(
    targets: &[super::super::workspace_index::IndexedCallTarget],
) -> Option<FunctionKey> {
    targets
        .iter()
        .find(|target| is_raw_target_role(target.role()))
        .map(super::super::workspace_index::IndexedCallTarget::callable)
}

fn raw_target_shape(
    targets: &[super::super::workspace_index::IndexedCallTarget],
) -> RawTargetShape {
    targets
        .iter()
        .filter(|target| is_raw_target_role(target.role()))
        .map(|target| (target.role(), target.callable().definition()))
        .collect()
}

fn semantic_shape_key(
    occurrence: &CallOccurrenceEntity,
    targets: &[super::super::workspace_index::IndexedCallTarget],
) -> SemanticShapeKey {
    SemanticShapeKey {
        kind: occurrence.kind(),
        raw_targets: raw_target_shape(targets),
        opaque_description: occurrence.opaque_target_description().map(str::to_owned),
    }
}

const fn is_raw_target_role(role: CallTargetRole) -> bool {
    matches!(
        role,
        CallTargetRole::Runtime | CallTargetRole::OpaqueTrait | CallTargetRole::OpaqueFunction
    )
}
