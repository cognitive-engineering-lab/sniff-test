//! Target-agnostic selection of proven body and followed-call trace routes.

use std::collections::{BTreeSet, HashMap};

#[cfg(test)]
use std::cell::Cell;

use crate::analysis::facts::composition::WorkspaceRelationRef;
use crate::analysis::facts::evaluation::RelationTrace;
use crate::analysis::facts::program::FunctionKey;
use crate::analysis::facts::program::root_traversal::{
    ResolvedBodyVisit, ResolvedFollowedCall, ResolvedMarkerClaim, ResolvedRootProgramTraversal,
};
use crate::analysis::facts::program::workspace_index::CallableSelectsFunctionBody;
use crate::analysis::facts::schema::RowSchema;
use crate::analysis::facts::workspace::{ArtifactScopeId, ScopedEntityRef};

/// A target-agnostic endpoint used to select its strict followed-call prefix.
#[derive(Clone, Copy)]
pub(super) struct TraceRouteEndpoint<'a> {
    order: u64,
    trace: &'a RelationTrace,
    inherited_markers: &'a [ResolvedMarkerClaim],
}

impl<'a> TraceRouteEndpoint<'a> {
    pub(super) const fn new(
        order: u64,
        trace: &'a RelationTrace,
        inherited_markers: &'a [ResolvedMarkerClaim],
    ) -> Self {
        Self {
            order,
            trace,
            inherited_markers,
        }
    }
}

/// Failure to select one structurally valid route from resolved traversal data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum TraceRouteError {
    MissingCallerBody { occurrence: ScopedEntityRef },
    AmbiguousCallerBody { occurrence: ScopedEntityRef },
    MissingEnteredBody { callable: ScopedEntityRef },
    AmbiguousEnteredBody { callable: ScopedEntityRef },
    TargetBodyMismatch { callable: ScopedEntityRef },
    InvalidTracePrefix,
    NonMonotonicTraversalOrder,
    MarkerRegression,
    DuplicateSelectedCall { occurrence: ScopedEntityRef },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TraceBodySelectionError {
    Missing,
    Ambiguous,
}

/// One selected followed call and the exact body states on either side.
#[derive(Clone, Copy)]
pub(super) struct SelectedTraceCall<'a> {
    call: &'a ResolvedFollowedCall,
    caller: &'a ResolvedBodyVisit,
    entered: &'a ResolvedBodyVisit,
}

impl<'a> SelectedTraceCall<'a> {
    pub(super) const fn call(&self) -> &'a ResolvedFollowedCall {
        self.call
    }

    pub(super) const fn caller(&self) -> &'a ResolvedBodyVisit {
        self.caller
    }
}

/// An already-validated strict followed-call prefix for one endpoint.
#[derive(Clone)]
pub(super) struct SelectedTraceRoute<'a> {
    calls: Vec<SelectedTraceCall<'a>>,
}

impl<'a> SelectedTraceRoute<'a> {
    pub(super) fn calls(&self) -> impl ExactSizeIterator<Item = &SelectedTraceCall<'a>> {
        self.calls.iter()
    }

    pub(super) fn validate_reuse(
        &self,
        endpoint: TraceRouteEndpoint<'_>,
    ) -> Result<(), TraceRouteError> {
        if self
            .calls
            .last()
            .is_some_and(|selected| selected.call.order() >= endpoint.order)
        {
            return Err(TraceRouteError::NonMonotonicTraversalOrder);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.calls.len()
    }

    #[cfg(test)]
    pub(super) fn swap_for_test(&mut self, left: usize, right: usize) {
        self.calls.swap(left, right);
    }

    #[cfg(test)]
    pub(super) fn validate_for_test(
        &self,
        endpoint: TraceRouteEndpoint<'_>,
    ) -> Result<(), TraceRouteError> {
        validate_call_route(&self.calls, endpoint)
    }
}

/// Root-local indexes and path-safe caches for selecting proven call routes.
pub(super) struct TraceRouteSelector<'a> {
    indexes: TraceRouteIndexes<'a>,
    call_selections: CallSelectionCache<'a>,
}

impl<'a> TraceRouteSelector<'a> {
    pub(super) fn prepare<B>(traversal: &'a ResolvedRootProgramTraversal<B>) -> Self {
        Self {
            indexes: TraceRouteIndexes::new(traversal),
            call_selections: CallSelectionCache::new(traversal.followed_calls().len()),
        }
    }

    pub(super) fn select_owner_body(
        &self,
        body: ScopedEntityRef,
        markers: &[ResolvedMarkerClaim],
        trace: &RelationTrace,
    ) -> Result<&'a ResolvedBodyVisit, TraceBodySelectionError> {
        self.indexes.select_owner_body(body, markers, trace)
    }

    pub(super) fn select_terminal_caller(
        &self,
        occurrence: &ScopedEntityRef,
        owner: FunctionKey,
        inherited_markers: &[ResolvedMarkerClaim],
        trace: &RelationTrace,
    ) -> Result<&'a ResolvedBodyVisit, TraceRouteError> {
        self.indexes
            .select_caller_body(occurrence, owner, inherited_markers, trace)
    }

    pub(super) fn select_route(
        &mut self,
        endpoint: TraceRouteEndpoint<'_>,
    ) -> Result<SelectedTraceRoute<'a>, TraceRouteError> {
        let calls = self
            .indexes
            .selected_call_route(endpoint, &mut self.call_selections)?;
        validate_call_route(&calls, endpoint)?;
        Ok(SelectedTraceRoute { calls })
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct MarkerKey(Vec<ScopedEntityRef>);

impl MarkerKey {
    fn new(markers: &[ResolvedMarkerClaim]) -> Self {
        record_marker_claims(markers.len());
        let mut claims = markers
            .iter()
            .map(|marker| marker.claim().erase())
            .collect::<Vec<_>>();
        claims.sort_unstable();
        claims.dedup();
        Self(claims)
    }

    fn is_subset_of(&self, other: &Self) -> bool {
        record_marker_claims(self.0.len());
        self.0
            .iter()
            .all(|claim| other.0.binary_search(claim).is_ok())
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct BodyOwnerIndexKey {
    body: ScopedEntityRef,
    markers: MarkerKey,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct CallerBodyIndexKey {
    scope: ArtifactScopeId,
    function: FunctionKey,
    markers: MarkerKey,
}

struct IndexedCall<'a> {
    index: usize,
    call: &'a ResolvedFollowedCall,
    active_markers: MarkerKey,
}

struct TraceTrieNode<T> {
    values: Vec<T>,
    children: HashMap<WorkspaceRelationRef, usize>,
}

impl<T> Default for TraceTrieNode<T> {
    fn default() -> Self {
        Self {
            values: Vec::new(),
            children: HashMap::new(),
        }
    }
}

struct TraceTrie<T> {
    roots: HashMap<ScopedEntityRef, usize>,
    nodes: Vec<TraceTrieNode<T>>,
}

impl<T> Default for TraceTrie<T> {
    fn default() -> Self {
        Self {
            roots: HashMap::new(),
            nodes: Vec::new(),
        }
    }
}

impl<T> TraceTrie<T> {
    fn insert(&mut self, trace: &RelationTrace, value: T) {
        let mut node = if let Some(node) = self.roots.get(trace.root()).copied() {
            node
        } else {
            let node = self.push_node();
            self.roots.insert(trace.root().clone(), node);
            node
        };
        for relation in trace.relations() {
            record_trie_edge();
            node = if let Some(child) = self.nodes[node].children.get(relation).copied() {
                child
            } else {
                let child = self.push_node();
                self.nodes[node].children.insert(relation.clone(), child);
                child
            };
        }
        self.nodes[node].values.push(value);
    }

    fn longest_prefix(&self, trace: &RelationTrace) -> Option<&[T]> {
        let mut node = self.roots.get(trace.root()).copied()?;
        let mut longest =
            (!self.nodes[node].values.is_empty()).then_some(self.nodes[node].values.as_slice());
        for relation in trace.relations() {
            record_trie_edge();
            let Some(child) = self.nodes[node].children.get(relation).copied() else {
                break;
            };
            node = child;
            if !self.nodes[node].values.is_empty() {
                longest = Some(self.nodes[node].values.as_slice());
            }
        }
        longest
    }

    fn exact_prefix(&self, trace: &RelationTrace, depth: usize) -> Option<&[T]> {
        if depth > trace.relations().len() {
            return None;
        }
        let mut node = self.roots.get(trace.root()).copied()?;
        for relation in &trace.relations()[..depth] {
            record_trie_edge();
            node = self.nodes[node].children.get(relation).copied()?;
        }
        (!self.nodes[node].values.is_empty()).then_some(self.nodes[node].values.as_slice())
    }

    fn for_each_strict_prefix(&self, trace: &RelationTrace, mut visit: impl FnMut(&T)) {
        if trace.relations().is_empty() {
            return;
        }
        let Some(mut node) = self.roots.get(trace.root()).copied() else {
            return;
        };
        for value in &self.nodes[node].values {
            visit(value);
        }
        for relation in &trace.relations()[..trace.relations().len() - 1] {
            record_trie_edge();
            let Some(child) = self.nodes[node].children.get(relation).copied() else {
                return;
            };
            node = child;
            for value in &self.nodes[node].values {
                visit(value);
            }
        }
    }

    fn sort_values_by_key<K: Ord>(&mut self, mut key: impl FnMut(&T) -> K) {
        for node in &mut self.nodes {
            node.values.sort_by_key(&mut key);
        }
    }

    fn push_node(&mut self) -> usize {
        let node = self.nodes.len();
        self.nodes.push(TraceTrieNode::default());
        node
    }
}

struct TraceRouteIndexes<'a> {
    bodies_by_owner: HashMap<BodyOwnerIndexKey, TraceTrie<&'a ResolvedBodyVisit>>,
    bodies_by_caller: HashMap<CallerBodyIndexKey, TraceTrie<&'a ResolvedBodyVisit>>,
    bodies_by_markers: HashMap<MarkerKey, TraceTrie<&'a ResolvedBodyVisit>>,
    calls_by_trace: TraceTrie<IndexedCall<'a>>,
}

impl<'a> TraceRouteIndexes<'a> {
    fn new<B>(traversal: &'a ResolvedRootProgramTraversal<B>) -> Self {
        let mut bodies_by_owner = HashMap::<BodyOwnerIndexKey, TraceTrie<_>>::new();
        let mut bodies_by_caller = HashMap::<CallerBodyIndexKey, TraceTrie<_>>::new();
        let mut bodies_by_markers = HashMap::<MarkerKey, TraceTrie<_>>::new();
        for visit in traversal.body_visits() {
            record_body_visit_indexed();
            let markers = MarkerKey::new(visit.active_markers());
            bodies_by_owner
                .entry(BodyOwnerIndexKey {
                    body: visit.body().erase(),
                    markers: markers.clone(),
                })
                .or_default()
                .insert(visit.trace(), visit);
            bodies_by_caller
                .entry(CallerBodyIndexKey {
                    scope: visit.body().scope().clone(),
                    function: visit.function(),
                    markers: markers.clone(),
                })
                .or_default()
                .insert(visit.trace(), visit);
            bodies_by_markers
                .entry(markers)
                .or_default()
                .insert(visit.trace(), visit);
        }

        let mut calls_by_trace = TraceTrie::default();
        for (index, call) in traversal.followed_calls().iter().enumerate() {
            record_followed_call_indexed();
            calls_by_trace.insert(
                call.trace(),
                IndexedCall {
                    index,
                    call,
                    active_markers: MarkerKey::new(call.active_markers()),
                },
            );
        }
        calls_by_trace.sort_values_by_key(|call| call.call.order());

        Self {
            bodies_by_owner,
            bodies_by_caller,
            bodies_by_markers,
            calls_by_trace,
        }
    }

    fn select_owner_body(
        &self,
        body: ScopedEntityRef,
        markers: &[ResolvedMarkerClaim],
        trace: &RelationTrace,
    ) -> Result<&'a ResolvedBodyVisit, TraceBodySelectionError> {
        let key = BodyOwnerIndexKey {
            body,
            markers: MarkerKey::new(markers),
        };
        self.bodies_by_owner
            .get(&key)
            .and_then(|index| index.longest_prefix(trace))
            .map_or(Err(TraceBodySelectionError::Missing), |candidates| {
                select_longest_body(candidates.iter().copied())
            })
    }

    fn selected_call_route(
        &self,
        endpoint: TraceRouteEndpoint<'_>,
        selections: &mut CallSelectionCache<'a>,
    ) -> Result<Vec<SelectedTraceCall<'a>>, TraceRouteError> {
        let endpoint_markers = MarkerKey::new(endpoint.inherited_markers);
        let mut selected = Vec::<SelectedTraceCall<'a>>::new();
        let mut selected_by_identity = HashMap::<(usize, ScopedEntityRef), usize>::new();
        let mut error = None;
        self.calls_by_trace
            .for_each_strict_prefix(endpoint.trace, |indexed| {
                if error.is_some() || !indexed.active_markers.is_subset_of(&endpoint_markers) {
                    return;
                }
                let call = indexed.call;
                let selected_call = (|| {
                    let selected_call = selections.select(self, indexed, endpoint)?;
                    let identity = (call.trace().relations().len(), call.occurrence().erase());
                    if let Some(existing_index) = selected_by_identity.get(&identity).copied() {
                        let existing = &mut selected[existing_index];
                        if existing.call.target() != call.target() {
                            return Err(TraceRouteError::DuplicateSelectedCall {
                                occurrence: call.occurrence().erase(),
                            });
                        }
                        if call.order() > existing.call.order() {
                            *existing = selected_call;
                        }
                    } else {
                        selected_by_identity.insert(identity, selected.len());
                        selected.push(selected_call);
                    }
                    Ok(())
                })();
                if let Err(found) = selected_call {
                    error = Some(found);
                }
            });
        if let Some(error) = error {
            return Err(error);
        }
        Ok(selected)
    }

    fn select_caller_body(
        &self,
        occurrence: &ScopedEntityRef,
        owner: FunctionKey,
        inherited_markers: &[ResolvedMarkerClaim],
        trace: &RelationTrace,
    ) -> Result<&'a ResolvedBodyVisit, TraceRouteError> {
        let key = CallerBodyIndexKey {
            scope: occurrence.scope().clone(),
            function: owner,
            markers: MarkerKey::new(inherited_markers),
        };
        self.bodies_by_caller
            .get(&key)
            .and_then(|index| index.longest_prefix(trace))
            .map_or(Err(TraceBodySelectionError::Missing), |candidates| {
                select_longest_body(candidates.iter().copied())
            })
            .map_err(|error| match error {
                TraceBodySelectionError::Missing => TraceRouteError::MissingCallerBody {
                    occurrence: occurrence.clone(),
                },
                TraceBodySelectionError::Ambiguous => TraceRouteError::AmbiguousCallerBody {
                    occurrence: occurrence.clone(),
                },
            })
    }

    fn select_entered_body(
        &self,
        call: &ResolvedFollowedCall,
        endpoint: TraceRouteEndpoint<'_>,
    ) -> Result<&'a ResolvedBodyVisit, TraceRouteError> {
        let entered_depth = call.trace().relations().len() + 1;
        entered_body_relation(call, endpoint.trace)?;
        let candidates = self
            .bodies_by_markers
            .get(&MarkerKey::new(call.active_markers()))
            .and_then(|index| index.exact_prefix(endpoint.trace, entered_depth))
            .filter(|_| entered_depth <= endpoint.trace.relations().len());
        let entered = candidates
            .map_or(Err(TraceBodySelectionError::Missing), |candidates| {
                select_longest_body(candidates.iter().copied())
            })
            .map_err(|error| match error {
                TraceBodySelectionError::Missing => TraceRouteError::MissingEnteredBody {
                    callable: call.target().callable().erase(),
                },
                TraceBodySelectionError::Ambiguous => TraceRouteError::AmbiguousEnteredBody {
                    callable: call.target().callable().erase(),
                },
            })?;
        validate_entered_body_function(
            &call.target().callable().erase(),
            entered.function(),
            *call.target_data().key(),
        )?;
        Ok(entered)
    }
}

fn validate_entered_body_function(
    callable: &ScopedEntityRef,
    entered_function: FunctionKey,
    callable_function: FunctionKey,
) -> Result<(), TraceRouteError> {
    let same_definition_generic_fallback = entered_function.instance().is_none()
        && callable_function.instance().is_some()
        && entered_function.definition() == callable_function.definition();
    if entered_function == callable_function || same_definition_generic_fallback {
        Ok(())
    } else {
        Err(TraceRouteError::TargetBodyMismatch {
            callable: callable.clone(),
        })
    }
}

fn entered_body_relation<'a>(
    call: &ResolvedFollowedCall,
    endpoint_trace: &'a RelationTrace,
) -> Result<&'a WorkspaceRelationRef, TraceRouteError> {
    endpoint_trace
        .relations()
        .get(call.trace().relations().len())
        .filter(|relation| relation.schema().as_str() == CallableSelectsFunctionBody::ID)
        .ok_or_else(|| TraceRouteError::MissingEnteredBody {
            callable: call.target().callable().erase(),
        })
}

struct CallSelectionCache<'a> {
    callers: Vec<Option<&'a ResolvedBodyVisit>>,
    entered: Vec<HashMap<WorkspaceRelationRef, &'a ResolvedBodyVisit>>,
}

impl<'a> CallSelectionCache<'a> {
    fn new(call_count: usize) -> Self {
        Self {
            callers: vec![None; call_count],
            entered: (0..call_count).map(|_| HashMap::new()).collect(),
        }
    }

    fn select(
        &mut self,
        indexes: &TraceRouteIndexes<'a>,
        candidate: &IndexedCall<'a>,
        endpoint: TraceRouteEndpoint<'_>,
    ) -> Result<SelectedTraceCall<'a>, TraceRouteError> {
        let caller = if let Some(caller) = self.callers[candidate.index] {
            caller
        } else {
            let occurrence = candidate.call.occurrence().erase();
            let caller = indexes.select_caller_body(
                &occurrence,
                *candidate.call.occurrence_data().key().owner(),
                candidate.call.inherited_markers(),
                candidate.call.trace(),
            )?;
            self.callers[candidate.index] = Some(caller);
            caller
        };
        let entered_relation = entered_body_relation(candidate.call, endpoint.trace)?.clone();
        let entered = if let Some(entered) = self.entered[candidate.index]
            .get(&entered_relation)
            .copied()
        {
            entered
        } else {
            let entered = indexes.select_entered_body(candidate.call, endpoint)?;
            self.entered[candidate.index].insert(entered_relation, entered);
            entered
        };
        Ok(SelectedTraceCall {
            call: candidate.call,
            caller,
            entered,
        })
    }
}

fn select_longest_body<'a>(
    candidates: impl Iterator<Item = &'a ResolvedBodyVisit>,
) -> Result<&'a ResolvedBodyVisit, TraceBodySelectionError> {
    let mut best: Option<&ResolvedBodyVisit> = None;
    for candidate in candidates {
        record_body_candidate();
        match best {
            None => best = Some(candidate),
            Some(current)
                if candidate.trace().relations().len() > current.trace().relations().len() =>
            {
                best = Some(candidate);
            }
            Some(current)
                if candidate.trace().relations().len() == current.trace().relations().len()
                    && (candidate.body() != current.body()
                        || candidate.trace() != current.trace()) =>
            {
                return Err(TraceBodySelectionError::Ambiguous);
            }
            Some(current)
                if candidate.trace() == current.trace() && candidate.order() > current.order() =>
            {
                best = Some(candidate);
            }
            Some(_) => {}
        }
    }
    best.ok_or(TraceBodySelectionError::Missing)
}

fn validate_call_route(
    route: &[SelectedTraceCall<'_>],
    endpoint: TraceRouteEndpoint<'_>,
) -> Result<(), TraceRouteError> {
    let mut previous_order = None;
    let mut previous_markers = BTreeSet::new();
    let mut previous_depth = None;
    for selected in route {
        if selected.entered.trace().relations().len() != selected.call.trace().relations().len() + 1
        {
            return Err(TraceRouteError::InvalidTracePrefix);
        }
        if previous_order.is_some_and(|order| selected.call.order() <= order)
            || selected.call.order() >= endpoint.order
        {
            return Err(TraceRouteError::NonMonotonicTraversalOrder);
        }
        let markers = marker_ids(selected.call.active_markers());
        if !previous_markers.is_subset(&markers) {
            return Err(TraceRouteError::MarkerRegression);
        }
        let depth = selected.call.trace().relations().len();
        if previous_depth == Some(depth) {
            return Err(TraceRouteError::DuplicateSelectedCall {
                occurrence: selected.call.occurrence().erase(),
            });
        }
        previous_order = Some(selected.call.order());
        previous_depth = Some(depth);
        previous_markers = markers;
    }
    if !previous_markers.is_subset(&marker_ids(endpoint.inherited_markers)) {
        return Err(TraceRouteError::MarkerRegression);
    }
    Ok(())
}

fn marker_ids(markers: &[ResolvedMarkerClaim]) -> BTreeSet<ScopedEntityRef> {
    record_marker_claims(markers.len());
    markers
        .iter()
        .map(|marker| marker.claim().erase())
        .collect()
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct TraceRouteWork {
    pub(super) body_visits: usize,
    pub(super) followed_calls: usize,
    pub(super) trie_edges: usize,
    pub(super) body_candidates: usize,
    pub(super) marker_claims: usize,
}

#[cfg(test)]
thread_local! {
    static TRACE_ROUTE_WORK: Cell<TraceRouteWork> = const {
        Cell::new(TraceRouteWork {
            body_visits: 0,
            followed_calls: 0,
            trie_edges: 0,
            body_candidates: 0,
            marker_claims: 0,
        })
    };
}

#[cfg(test)]
pub(super) fn reset_trace_route_work() {
    TRACE_ROUTE_WORK.set(TraceRouteWork::default());
}

#[cfg(test)]
pub(super) fn trace_route_work() -> TraceRouteWork {
    TRACE_ROUTE_WORK.get()
}

#[cfg(test)]
fn record_body_visit_indexed() {
    TRACE_ROUTE_WORK.with(|counter| {
        let mut work = counter.get();
        work.body_visits += 1;
        counter.set(work);
    });
}

#[cfg(not(test))]
fn record_body_visit_indexed() {}

#[cfg(test)]
fn record_followed_call_indexed() {
    TRACE_ROUTE_WORK.with(|counter| {
        let mut work = counter.get();
        work.followed_calls += 1;
        counter.set(work);
    });
}

#[cfg(not(test))]
fn record_followed_call_indexed() {}

#[cfg(test)]
fn record_trie_edge() {
    TRACE_ROUTE_WORK.with(|counter| {
        let mut work = counter.get();
        work.trie_edges += 1;
        counter.set(work);
    });
}

#[cfg(not(test))]
fn record_trie_edge() {}

#[cfg(test)]
fn record_body_candidate() {
    TRACE_ROUTE_WORK.with(|counter| {
        let mut work = counter.get();
        work.body_candidates += 1;
        counter.set(work);
    });
}

#[cfg(not(test))]
fn record_body_candidate() {}

#[cfg(test)]
fn record_marker_claims(count: usize) {
    TRACE_ROUTE_WORK.with(|counter| {
        let mut work = counter.get();
        work.marker_claims += count;
        counter.set(work);
    });
}

#[cfg(not(test))]
fn record_marker_claims(_count: usize) {}

#[cfg(test)]
mod tests {
    use super::{TraceRouteError, validate_entered_body_function};
    use crate::analysis::facts::encoded::EntityRef;
    use crate::analysis::facts::panic::compiler_assert_trace::tests::{definition, instance};
    use crate::analysis::facts::program::FunctionKey;
    use crate::analysis::facts::schema::SchemaId;
    use crate::analysis::facts::workspace::{ArtifactScopeId, ScopedEntityRef};

    fn callable() -> ScopedEntityRef {
        ScopedEntityRef::new(
            ArtifactScopeId::for_in_memory(1, 0),
            EntityRef {
                schema: SchemaId::new("sniff-test.core.callable").unwrap(),
                row: 0,
            },
        )
    }

    #[test]
    fn entered_body_compatibility_rejects_every_fallback_except_exact_to_same_generic() {
        let callable = callable();
        let exact = FunctionKey::new(definition(1), Some(instance(1)));
        let generic = FunctionKey::new(definition(1), None);
        assert_eq!(
            validate_entered_body_function(&callable, exact, exact),
            Ok(())
        );
        assert_eq!(
            validate_entered_body_function(&callable, generic, exact),
            Ok(())
        );

        let different_generic = FunctionKey::new(definition(2), None);
        assert_eq!(
            validate_entered_body_function(&callable, different_generic, exact),
            Err(TraceRouteError::TargetBodyMismatch {
                callable: callable.clone(),
            })
        );
        let different_exact = FunctionKey::new(definition(1), Some(instance(2)));
        assert_eq!(
            validate_entered_body_function(&callable, different_exact, exact),
            Err(TraceRouteError::TargetBodyMismatch {
                callable: callable.clone(),
            })
        );
        assert_eq!(
            validate_entered_body_function(&callable, exact, generic),
            Err(TraceRouteError::TargetBodyMismatch { callable })
        );
    }
}
