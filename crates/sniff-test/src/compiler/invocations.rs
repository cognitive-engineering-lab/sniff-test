use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use effect_tracing::{
    EffectGraph, FunctionId, InvocationId, TransparentBodyEdgeId, UnknownBoundary,
};

use crate::artifact::same_call_source_site;
use crate::artifact::{
    ArtifactFacts, CallFact, CallId, CallKindFact, CallSiteId, CallTargetFact,
    FunctionId as StableFunctionId, FunctionTargetFact, IndirectCallKindFact, MacroExpansionFact,
    same_macro_provenance,
};
use crate::namespace::StableDefPathHash;

/// A source-level invocation target.
///
/// Concrete targets participate in Panic/Safety reverse propagation.
/// `Unknown` records the unresolved implementation without inventing a callee.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum CallTarget {
    Function(FunctionId),
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InvocationResolution {
    Resolved,
    PartiallyResolved { reason: UnresolvedCallTargetReason },
    Unresolved { reason: UnresolvedCallTargetReason },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnresolvedCallTargetReason {
    FunctionPointer,
    DynamicDispatch,
    GenericDispatch,
    UnavailableBody,
    Opaque,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Invocation {
    id: InvocationId,
    caller: FunctionId,
    targets: Vec<CallTarget>,
    /// Callable surface declarations represented by this source-level site.
    /// Compiler desugarings such as `for` may place several declaration calls
    /// at one source site; these are contract metadata, not runtime targets.
    declarations: Vec<FunctionId>,
    raw_calls: Vec<CallId>,
    raw_edges: Vec<CallFact>,
    /// Every observed display alias for each stable macro expansion frame.
    /// Grouped raw edges can name one macro definition through different
    /// re-export paths, and policy matching must not depend on raw `CallId`.
    macro_provenance: Vec<MacroExpansionFact>,
}

impl Invocation {
    #[must_use]
    pub(crate) const fn id(&self) -> InvocationId {
        self.id
    }

    #[must_use]
    pub(crate) const fn caller(&self) -> FunctionId {
        self.caller
    }

    #[must_use]
    pub(crate) fn raw_calls(&self) -> &[CallId] {
        &self.raw_calls
    }

    pub(crate) fn declaration_targets(&self) -> impl Iterator<Item = FunctionId> + '_ {
        self.declarations.iter().copied()
    }

    pub(crate) fn function_targets(&self) -> impl Iterator<Item = FunctionId> + '_ {
        self.targets.iter().filter_map(|target| match target {
            CallTarget::Function(function) => Some(*function),
            CallTarget::Unknown => None,
        })
    }

    #[must_use]
    pub(crate) fn macro_provenance(&self) -> &[MacroExpansionFact] {
        &self.macro_provenance
    }

    #[must_use]
    pub(crate) fn is_builtin_unsafe(&self) -> bool {
        !self.raw_edges.is_empty() && self.raw_edges.iter().all(|edge| edge.inside_builtin_unsafe)
    }

    #[must_use]
    pub(crate) fn is_unresolved(&self) -> bool {
        self.targets.contains(&CallTarget::Unknown)
    }

    #[must_use]
    pub(crate) fn resolution(&self) -> InvocationResolution {
        if !self.is_unresolved() {
            return InvocationResolution::Resolved;
        }
        let reason = self.unresolved_reason();
        if self
            .targets
            .iter()
            .any(|target| matches!(target, CallTarget::Function(_)))
        {
            InvocationResolution::PartiallyResolved { reason }
        } else {
            InvocationResolution::Unresolved { reason }
        }
    }

    fn unresolved_reason(&self) -> UnresolvedCallTargetReason {
        if self
            .raw_edges
            .iter()
            .any(|edge| edge.indirect_kind == Some(IndirectCallKindFact::DynamicDispatch))
        {
            return UnresolvedCallTargetReason::DynamicDispatch;
        }
        if self
            .raw_edges
            .iter()
            .any(|edge| edge.indirect_kind == Some(IndirectCallKindFact::FunctionPointer))
        {
            return UnresolvedCallTargetReason::FunctionPointer;
        }
        if self
            .raw_edges
            .iter()
            .any(|edge| edge.declaration_target.is_some())
        {
            return UnresolvedCallTargetReason::GenericDispatch;
        }
        if self.raw_edges.iter().any(|edge| {
            edge.target.function_target().is_some_and(|target| {
                !target.attributes.is_foreign && !target.attributes.has_rust_body
            })
        }) {
            return UnresolvedCallTargetReason::UnavailableBody;
        }
        UnresolvedCallTargetReason::Opaque
    }
}

/// Minimal reverse invocation view consumed by [`effect_tracing::EffectEngine`].
pub(crate) struct InvocationGraph {
    stable_functions: Vec<StableFunctionId>,
    body_functions: BTreeSet<StableFunctionId>,
    functions: BTreeMap<StableFunctionId, FunctionId>,
    functions_by_definition: BTreeMap<StableDefPathHash, Vec<FunctionId>>,
    invocations: Vec<Invocation>,
    invocations_by_caller_definition: BTreeMap<StableDefPathHash, Vec<InvocationId>>,
    incoming: Vec<Vec<InvocationId>>,
    comment_incoming: Vec<Vec<InvocationId>>,
    declaration_fallbacks: Vec<Option<StableFunctionId>>,
    transparent_parents: Vec<Vec<TransparentBodyEdgeId>>,
    transparent_parent: Vec<FunctionId>,
    transparent_source: Vec<CallFact>,
    raw_call_invocations: BTreeMap<(StableFunctionId, CallId), InvocationId>,
}

impl InvocationGraph {
    pub(crate) fn from_artifact(artifact: &ArtifactFacts) -> Result<Self, InvocationGraphError> {
        let transparent_owners = collect_transparent_owners(artifact);
        let stable_functions = collect_functions(artifact);
        let functions = stable_functions
            .iter()
            .copied()
            .enumerate()
            .map(|(index, function)| (function, FunctionId::from_index(index)))
            .collect::<BTreeMap<_, _>>();
        let mut functions_by_definition = BTreeMap::<StableDefPathHash, Vec<FunctionId>>::new();
        for (function, id) in &functions {
            functions_by_definition
                .entry(function.def_path_hash)
                .or_default()
                .push(*id);
        }
        let mut graph = Self {
            incoming: vec![Vec::new(); stable_functions.len()],
            comment_incoming: vec![Vec::new(); stable_functions.len()],
            declaration_fallbacks: vec![None; stable_functions.len()],
            transparent_parents: vec![Vec::new(); stable_functions.len()],
            stable_functions,
            body_functions: artifact
                .functions
                .iter()
                .map(|body| body.function)
                .collect(),
            functions,
            functions_by_definition,
            invocations: Vec::new(),
            invocations_by_caller_definition: BTreeMap::new(),
            transparent_parent: Vec::new(),
            transparent_source: Vec::new(),
            raw_call_invocations: BTreeMap::new(),
        };

        for body in &artifact.functions {
            if let Some(declaration) = &body.contract_declaration {
                let implementations = graph.function_aliases(body.function).collect::<Vec<_>>();
                for implementation in implementations {
                    graph.set_declaration_fallback(implementation, declaration.function)?;
                }
            }
        }
        for body in &artifact.functions {
            let calls = body
                .calls
                .iter()
                .map(|call| normalize_transparent_target(call, artifact, &transparent_owners))
                .collect::<Vec<_>>();
            graph.collect_body(body.function, &calls)?;
        }
        Ok(graph)
    }

    #[must_use]
    pub(crate) fn function(&self, stable: StableFunctionId) -> Option<FunctionId> {
        stable
            .resolution_candidates()
            .find_map(|candidate| self.functions.get(&candidate).copied())
    }

    fn invocation_target(&self, stable: StableFunctionId) -> Option<FunctionId> {
        stable
            .resolution_candidates()
            .find(|candidate| self.body_functions.contains(candidate))
            .and_then(|candidate| self.functions.get(&candidate).copied())
            .or_else(|| self.function(stable))
    }

    #[must_use]
    pub(crate) fn stable_function(&self, function: FunctionId) -> StableFunctionId {
        self.stable_functions[function.index()]
    }

    /// Returns every exact or generic graph identity for one source definition.
    pub(crate) fn function_aliases(
        &self,
        stable: StableFunctionId,
    ) -> impl Iterator<Item = FunctionId> + '_ {
        self.functions_by_definition
            .get(&stable.def_path_hash)
            .into_iter()
            .flatten()
            .copied()
    }

    /// Resolves source-level trait/function contracts onto their concrete
    /// invocation targets without changing invocation identity.
    pub(crate) fn contract_targets(
        &self,
        contract_owner: StableFunctionId,
    ) -> BTreeSet<FunctionId> {
        let owner_aliases = self
            .function_aliases(contract_owner)
            .collect::<BTreeSet<_>>();
        let mut targets = owner_aliases.clone();
        targets.extend(
            self.declaration_fallbacks
                .iter()
                .enumerate()
                .filter(|(_, declaration)| {
                    declaration.is_some_and(|declaration| {
                        declaration.def_path_hash == contract_owner.def_path_hash
                    })
                })
                .map(|(index, _)| FunctionId::from_index(index)),
        );
        targets
    }

    /// Trait/interface declarations whose contract is the fallback for one
    /// compiler-resolved implementation.
    pub(crate) fn contract_declaration(&self, function: FunctionId) -> Option<StableFunctionId> {
        self.declaration_fallbacks[function.index()]
    }

    fn set_declaration_fallback(
        &mut self,
        function: FunctionId,
        declaration: StableFunctionId,
    ) -> Result<(), InvocationGraphError> {
        let fallback = &mut self.declaration_fallbacks[function.index()];
        match *fallback {
            None => *fallback = Some(declaration),
            Some(existing) if existing.def_path_hash == declaration.def_path_hash => {}
            Some(existing) => {
                return Err(InvocationGraphError::new(format!(
                    "implementation {:?} has conflicting contract declarations {existing:?} and {declaration:?}",
                    self.stable_functions[function.index()],
                )));
            }
        }
        Ok(())
    }

    /// A graph view that additionally lets `CommentEffect` cross a declaration
    /// edge. Concrete Panic/Safety effects deliberately use the base graph.
    #[must_use]
    pub(crate) const fn comment_graph(&self) -> CommentInvocationGraph<'_> {
        CommentInvocationGraph { graph: self }
    }

    /// Finds monomorphized/defining projections of one physical source call.
    pub(crate) fn invocation_aliases(&self, invocation: InvocationId) -> Vec<InvocationId> {
        let source = self.invocation(invocation);
        let source_caller = self.stable_function(source.caller);
        let source_edge = source.raw_edges.first();
        self.invocations_by_caller_definition
            .get(&source_caller.def_path_hash)
            .into_iter()
            .flatten()
            .copied()
            .filter(|candidate| {
                let candidate = self.invocation(*candidate);
                let candidate_caller = self.stable_function(candidate.caller);
                source_edge
                    .zip(candidate.raw_edges.first())
                    .is_some_and(|(left, right)| {
                        left.source_range == right.source_range
                            && left.expanded_range == right.expanded_range
                            && left.callee_range == right.callee_range
                            && same_macro_provenance(
                                &left.macro_expansions,
                                &right.macro_expansions,
                            )
                            && (candidate_caller == source_caller
                                && left.call_site == right.call_site
                                || candidate_caller != source_caller
                                    && has_source_projection_provenance(left))
                    })
            })
            .collect()
    }

    /// Projects one body-local raw call onto the corresponding call in an
    /// invocation alias. Raw `CallId`s are assigned independently in defining
    /// and monomorphized bodies, so equal numeric IDs are not evidence of the
    /// same physical source call.
    #[must_use]
    pub(crate) fn projected_raw_call(
        &self,
        invocation: InvocationId,
        call: CallId,
        alias: InvocationId,
    ) -> Option<CallId> {
        if invocation == alias {
            return self
                .invocation(alias)
                .raw_calls()
                .contains(&call)
                .then_some(call);
        }
        let source = self
            .source_edges(invocation)
            .iter()
            .find(|edge| edge.id == call)?;
        let mut matches = self
            .source_edges(alias)
            .iter()
            .filter(|candidate| same_call_source_site(source, candidate))
            .map(|candidate| candidate.id);
        let projected = matches.next()?;
        matches.next().is_none().then_some(projected)
    }

    #[must_use]
    pub(crate) fn invocation(&self, invocation: InvocationId) -> &Invocation {
        &self.invocations[invocation.index()]
    }

    pub(crate) fn invocations(&self) -> impl ExactSizeIterator<Item = &Invocation> {
        self.invocations.iter()
    }

    /// Returns the source call projection that reaches this concrete target.
    #[must_use]
    pub(crate) fn source_edge(
        &self,
        invocation: InvocationId,
        target: FunctionId,
    ) -> Option<&CallFact> {
        let invocation = self.invocation(invocation);
        invocation
            .raw_edges
            .iter()
            .find(|edge| {
                graph_target(edge).is_some_and(|stable| {
                    self.stable_function(target).def_path_hash == stable.def_path_hash
                })
            })
            .or_else(|| invocation.raw_edges.first())
    }

    #[must_use]
    pub(crate) fn source_edges(&self, invocation: InvocationId) -> &[CallFact] {
        &self.invocation(invocation).raw_edges
    }

    pub(crate) fn raw_calls_reaching(
        &self,
        invocation: InvocationId,
        target: FunctionId,
    ) -> impl Iterator<Item = CallId> + '_ {
        self.source_edges(invocation)
            .iter()
            .filter(move |edge| self.raw_edge_reaches(edge, target))
            .map(|edge| edge.id)
    }

    fn raw_edge_reaches(&self, edge: &CallFact, target: FunctionId) -> bool {
        concrete_target(edge)
            .and_then(|function| self.invocation_target(function))
            .is_some_and(|function| function == target)
            || declaration_target(edge)
                .and_then(|function| self.function(function))
                .is_some_and(|function| function == target)
    }

    #[must_use]
    pub(crate) fn transparent_source(&self, edge: TransparentBodyEdgeId) -> &CallFact {
        &self.transparent_source[edge.index()]
    }

    #[must_use]
    pub(crate) fn invocation_for_raw_call(
        &self,
        caller: StableFunctionId,
        call: CallId,
    ) -> Option<InvocationId> {
        self.raw_call_invocations.get(&(caller, call)).copied()
    }

    fn collect_body(
        &mut self,
        stable_caller: StableFunctionId,
        calls: &[CallFact],
    ) -> Result<(), InvocationGraphError> {
        let caller = self.function(stable_caller).ok_or_else(|| {
            InvocationGraphError::new(format!("missing caller function {stable_caller:?}"))
        })?;
        let mut pending = BTreeMap::<CallSiteId, PendingInvocation>::new();

        for call in calls {
            if is_transparent(call.kind) {
                if let Some(target) = concrete_target(call) {
                    self.add_transparent(caller, target, call.clone())?;
                }
                continue;
            }
            if !is_invocation(call.kind) {
                continue;
            }

            self.collect_invocation_edge(caller, call.clone(), &mut pending)?;
        }

        for (_, pending) in pending {
            self.add_invocation(stable_caller, pending);
        }
        Ok(())
    }

    fn collect_invocation_edge(
        &mut self,
        caller: FunctionId,
        call: CallFact,
        pending: &mut BTreeMap<CallSiteId, PendingInvocation>,
    ) -> Result<(), InvocationGraphError> {
        let invocation = pending
            .entry(call.call_site)
            .or_insert_with(|| PendingInvocation::new(caller, call.macro_expansions.clone()));
        if !same_macro_provenance(&invocation.macro_provenance, &call.macro_expansions) {
            return Err(InvocationGraphError::new(format!(
                "source invocation {} in {:?} has inconsistent macro provenance",
                call.call_site.index(),
                self.stable_function(caller),
            )));
        }
        invocation.raw_calls.push(call.id);
        match (
            &call.target,
            concrete_target(&call),
            declaration_target(&call),
        ) {
            (CallTargetFact::Function(_), Some(target), _) => {
                let target = self.invocation_target(target).ok_or_else(|| {
                    InvocationGraphError::new(format!(
                        "missing invocation target function {target:?}"
                    ))
                })?;
                invocation.targets.insert(CallTarget::Function(target));
                if let Some(declaration) = call
                    .declaration_target
                    .as_ref()
                    .map(|target| target.function)
                {
                    self.set_declaration_fallback(target, declaration)?;
                }
            }
            (CallTargetFact::OpaqueBoundary { .. }, _, Some(target)) => {
                let target = self.function(target).ok_or_else(|| {
                    InvocationGraphError::new(format!(
                        "missing invocation declaration function {target:?}"
                    ))
                })?;
                invocation.declarations.insert(target);
            }
            _ => {
                invocation.targets.insert(CallTarget::Unknown);
            }
        }
        if matches!(call.target, CallTargetFact::OpaqueBoundary { .. }) {
            invocation.targets.insert(CallTarget::Unknown);
        }
        if call.target.function_target().is_some_and(|target| {
            !target.attributes.has_rust_body
                && !target.attributes.is_foreign
                && !target
                    .function
                    .resolution_candidates()
                    .any(|candidate| self.body_functions.contains(&candidate))
        }) {
            invocation.targets.insert(CallTarget::Unknown);
        }
        invocation.raw_edges.push(call);
        Ok(())
    }

    fn add_invocation(&mut self, stable_caller: StableFunctionId, mut pending: PendingInvocation) {
        pending.raw_calls.sort();
        pending.raw_calls.dedup();
        let id = InvocationId::from_index(self.invocations.len());
        let macro_provenance = collect_macro_provenance_aliases(&pending.raw_edges);
        let invocation = Invocation {
            id,
            caller: pending.caller,
            targets: pending.targets.into_iter().collect(),
            declarations: pending.declarations.into_iter().collect(),
            raw_calls: pending.raw_calls,
            raw_edges: pending.raw_edges,
            macro_provenance,
        };
        for target in &invocation.targets {
            if let CallTarget::Function(function) = target
                && !self.incoming[function.index()].contains(&id)
            {
                self.incoming[function.index()].push(id);
            }
            if let CallTarget::Function(function) = target
                && !self.comment_incoming[function.index()].contains(&id)
            {
                self.comment_incoming[function.index()].push(id);
            }
        }
        for declaration in &invocation.declarations {
            if !self.comment_incoming[declaration.index()].contains(&id) {
                self.comment_incoming[declaration.index()].push(id);
            }
        }
        for call in &invocation.raw_calls {
            self.raw_call_invocations.insert((stable_caller, *call), id);
        }
        self.invocations_by_caller_definition
            .entry(stable_caller.def_path_hash)
            .or_default()
            .push(id);
        self.invocations.push(invocation);
    }

    fn add_transparent(
        &mut self,
        parent: FunctionId,
        stable_child: StableFunctionId,
        source: CallFact,
    ) -> Result<(), InvocationGraphError> {
        let child = self.function(stable_child).ok_or_else(|| {
            InvocationGraphError::new(format!(
                "missing transparent child function {stable_child:?}"
            ))
        })?;
        let id = TransparentBodyEdgeId::from_index(self.transparent_parent.len());
        self.transparent_parent.push(parent);
        self.transparent_source.push(source);
        self.transparent_parents[child.index()].push(id);
        Ok(())
    }
}

fn collect_macro_provenance_aliases(raw_edges: &[CallFact]) -> Vec<MacroExpansionFact> {
    let Some(first) = raw_edges.first() else {
        return Vec::new();
    };
    let mut provenance = Vec::new();
    for index in 0..first.macro_expansions.len() {
        let mut aliases = raw_edges
            .iter()
            .map(|edge| edge.macro_expansions[index].clone())
            .collect::<Vec<_>>();
        aliases.sort_by(|left, right| left.display_path.cmp(&right.display_path));
        aliases.dedup();
        provenance.extend(aliases);
    }
    provenance
}

impl EffectGraph for InvocationGraph {
    fn incoming_invocations(&self, function: FunctionId) -> &[InvocationId] {
        &self.incoming[function.index()]
    }

    fn caller(&self, invocation: InvocationId) -> FunctionId {
        self.invocation(invocation).caller
    }

    fn transparent_parents(&self, function: FunctionId) -> &[TransparentBodyEdgeId] {
        &self.transparent_parents[function.index()]
    }

    fn transparent_parent(&self, edge: TransparentBodyEdgeId) -> FunctionId {
        self.transparent_parent[edge.index()]
    }

    fn unknown_boundaries(&self, _function: FunctionId) -> &[UnknownBoundary] {
        &[]
    }
}

/// `CommentEffect`'s contract-only extension of the minimal invocation graph.
pub(crate) struct CommentInvocationGraph<'graph> {
    graph: &'graph InvocationGraph,
}

impl EffectGraph for CommentInvocationGraph<'_> {
    fn incoming_invocations(&self, function: FunctionId) -> &[InvocationId] {
        &self.graph.comment_incoming[function.index()]
    }

    fn caller(&self, invocation: InvocationId) -> FunctionId {
        self.graph.caller(invocation)
    }

    fn transparent_parents(&self, function: FunctionId) -> &[TransparentBodyEdgeId] {
        self.graph.transparent_parents(function)
    }

    fn transparent_parent(&self, edge: TransparentBodyEdgeId) -> FunctionId {
        self.graph.transparent_parent(edge)
    }

    fn unknown_boundaries(&self, function: FunctionId) -> &[UnknownBoundary] {
        self.graph.unknown_boundaries(function)
    }
}

fn has_source_projection_provenance(call: &CallFact) -> bool {
    call.source_range.is_some()
        || call.expanded_range.is_some()
        || call.callee_range.is_some()
        || !call.macro_expansions.is_empty()
}

struct PendingInvocation {
    caller: FunctionId,
    targets: BTreeSet<CallTarget>,
    declarations: BTreeSet<FunctionId>,
    raw_calls: Vec<CallId>,
    raw_edges: Vec<CallFact>,
    macro_provenance: Vec<MacroExpansionFact>,
}

impl PendingInvocation {
    fn new(caller: FunctionId, macro_provenance: Vec<MacroExpansionFact>) -> Self {
        Self {
            caller,
            targets: BTreeSet::new(),
            declarations: BTreeSet::new(),
            raw_calls: Vec::new(),
            raw_edges: Vec::new(),
            macro_provenance,
        }
    }
}

fn collect_functions(artifact: &ArtifactFacts) -> Vec<StableFunctionId> {
    let mut functions = artifact
        .functions
        .iter()
        .map(|body| body.function)
        .collect::<BTreeSet<_>>();
    functions.extend(
        artifact
            .functions
            .iter()
            .filter_map(|body| body.contract_declaration.as_ref())
            .map(|declaration| declaration.function),
    );
    for call in artifact.functions.iter().flat_map(|body| &body.calls) {
        if let Some(target) = graph_target(call) {
            functions.insert(target);
        }
    }
    functions.into_iter().collect()
}

fn collect_transparent_owners(
    artifact: &ArtifactFacts,
) -> BTreeMap<StableFunctionId, StableFunctionId> {
    artifact
        .functions
        .iter()
        .flat_map(|body| {
            body.calls.iter().filter_map(move |call| {
                (is_transparent(call.kind))
                    .then(|| concrete_target(call).map(|child| (child, body.function)))
                    .flatten()
            })
        })
        .collect()
}

fn normalize_transparent_target(
    call: &CallFact,
    artifact: &ArtifactFacts,
    transparent_owners: &BTreeMap<StableFunctionId, StableFunctionId>,
) -> CallFact {
    if !is_invocation(call.kind) {
        return call.clone();
    }
    let mut normalized = call.clone();
    if let CallTargetFact::Function(target) = &mut normalized.target {
        *target = normalize_function_target(target, artifact, transparent_owners);
    }
    normalized
}

fn normalize_function_target(
    target: &FunctionTargetFact,
    artifact: &ArtifactFacts,
    transparent_owners: &BTreeMap<StableFunctionId, StableFunctionId>,
) -> FunctionTargetFact {
    let mut function = target.function;
    while let Some(parent) = transparent_owners.get(&function).copied() {
        function = parent;
    }
    if function == target.function {
        return target.clone();
    }
    artifact.function_body(function).map_or_else(
        || target.clone(),
        |body| FunctionTargetFact {
            function,
            display_path: body.display_path.clone(),
            attributes: body.attributes.clone(),
            contracts: crate::artifact::FunctionContractsFact::default(),
        },
    )
}

fn concrete_target(call: &CallFact) -> Option<StableFunctionId> {
    match &call.target {
        CallTargetFact::Function(target) => Some(target.function),
        CallTargetFact::OpaqueBoundary { .. } => None,
    }
}

fn declaration_target(call: &CallFact) -> Option<StableFunctionId> {
    call.declaration_target
        .as_ref()
        .map(|target| target.function)
        .or(match &call.target {
            CallTargetFact::OpaqueBoundary {
                target:
                    Some(
                        crate::artifact::OpaqueTargetFact::Trait(target)
                        | crate::artifact::OpaqueTargetFact::Function(target),
                    ),
                ..
            } => Some(target.function),
            CallTargetFact::Function(_) | CallTargetFact::OpaqueBoundary { target: None, .. } => {
                None
            }
        })
}

fn graph_target(call: &CallFact) -> Option<StableFunctionId> {
    concrete_target(call).or_else(|| declaration_target(call))
}

const fn is_invocation(kind: CallKindFact) -> bool {
    matches!(
        kind,
        CallKindFact::DirectCall | CallKindFact::TailCall | CallKindFact::IndirectCall
    )
}

const fn is_transparent(kind: CallKindFact) -> bool {
    matches!(kind, CallKindFact::ConstBody | CallKindFact::CoroutineBody)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InvocationGraphError {
    message: String,
}

impl InvocationGraphError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for InvocationGraphError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for InvocationGraphError {}

#[cfg(test)]
mod tests {
    use effect_tracing::{EffectEngine, EffectGraph};

    use crate::annotations::AnnotationIndex;
    use crate::artifact::{
        ArtifactFacts, CallFact, CallId, CallKindFact, CallSiteId, CallTargetFact,
        CompilerAssertKind, EffectFact, EffectFactKind, EffectId, FunctionAttributesFact,
        FunctionContractsFact, FunctionFact, FunctionFactProvenance,
        FunctionId as StableFunctionId, FunctionTargetFact, IndirectCallKindFact,
        MacroExpansionFact, OpaqueTargetFact, SafetyEffectGroupId, SourceFileFact, SourceFileId,
        SourceRangeFact, StableInstanceHash,
    };
    use crate::config::PanicConfig;
    use crate::effects::panic::{PanicEffect, PanicTermination};
    use crate::namespace::StableDefPathHash;

    use super::{CallTarget, InvocationGraph, InvocationResolution, UnresolvedCallTargetReason};

    fn stable_function(index: u64) -> StableFunctionId {
        let value = format!("{index:016x}{:016x}", index + 100);
        let hash = serde_json::from_str::<StableDefPathHash>(&format!("\"{value}\""))
            .expect("valid stable hash");
        StableFunctionId::generic(hash)
    }

    fn exact_function(definition: StableFunctionId, index: u64) -> StableFunctionId {
        let value = format!("{index:016x}{:016x}", index + 200);
        let instance = serde_json::from_str::<StableInstanceHash>(&format!("\"{value}\""))
            .expect("valid stable instance hash");
        StableFunctionId::exact(definition.def_path_hash, instance)
    }

    fn attributes() -> FunctionAttributesFact {
        FunctionAttributesFact {
            is_unsafe: false,
            is_exported: true,
            has_rust_body: true,
            is_foreign: false,
            namespace_candidates: vec![String::from("sample")],
        }
    }

    fn target(function: StableFunctionId) -> CallTargetFact {
        CallTargetFact::Function(FunctionTargetFact {
            function,
            display_path: format!("function-{}", function.def_path_hash),
            attributes: attributes(),
            contracts: FunctionContractsFact::default(),
        })
    }

    fn opaque() -> CallTargetFact {
        CallTargetFact::OpaqueBoundary {
            description: String::from("indirect call"),
            target: Some(OpaqueTargetFact::Function(FunctionTargetFact {
                function: stable_function(99),
                display_path: String::from("opaque declaration"),
                attributes: attributes(),
                contracts: FunctionContractsFact::default(),
            })),
        }
    }

    fn opaque_trait_declaration(function: StableFunctionId, description: &str) -> CallTargetFact {
        let CallTargetFact::Function(target) = target(function) else {
            unreachable!("target helper always creates a function target")
        };
        CallTargetFact::OpaqueBoundary {
            description: description.to_owned(),
            target: Some(OpaqueTargetFact::Trait(target)),
        }
    }

    fn call(id: u32, site: u32, kind: CallKindFact, target: CallTargetFact) -> CallFact {
        CallFact {
            id: CallId::new(id),
            call_site: CallSiteId::new(site),
            kind,
            safety_effect_group: Some(SafetyEffectGroupId::new(site)),
            requires_unsafe: false,
            inside_builtin_unsafe: false,
            source_range: None,
            expanded_range: None,
            macro_expansions: Vec::new(),
            callee_range: None,
            indirect_kind: None,
            declaration_target: None,
            target,
        }
    }

    fn body(function: StableFunctionId, calls: Vec<CallFact>) -> FunctionFact {
        FunctionFact {
            function,
            provenance: FunctionFactProvenance::DefiningArtifact,
            display_path: format!("function-{}", function.def_path_hash),
            attributes: attributes(),
            contract_declaration: None,
            source_range: None,
            calls,
            effects: Vec::new(),
            markers: Vec::new(),
            unverified_marker_probes: Vec::new(),
        }
    }

    fn body_with_contract_declaration(
        function: StableFunctionId,
        declaration: StableFunctionId,
    ) -> FunctionFact {
        let mut body = body(function, Vec::new());
        let CallTargetFact::Function(declaration) = target(declaration) else {
            unreachable!("target helper always creates a function target")
        };
        body.contract_declaration = Some(declaration);
        body
    }

    fn artifact(bodies: Vec<FunctionFact>) -> ArtifactFacts {
        ArtifactFacts::new(bodies, Vec::new()).expect("valid direct artifact facts")
    }

    fn source_file() -> SourceFileFact {
        SourceFileFact {
            id: SourceFileId::new("source-1"),
            filename: String::from("src/lib.rs"),
            content_hash: String::from("sha256:0123456789abcdef"),
            byte_len: 100,
        }
    }

    fn source_range(start: u64, end: u64) -> SourceRangeFact {
        SourceRangeFact {
            file: SourceFileId::new("source-1"),
            byte_start: start,
            byte_end: end,
        }
    }

    #[test]
    fn direct_and_tail_calls_are_indexed_in_reverse() {
        let root = stable_function(0);
        let middle = stable_function(1);
        let leaf = stable_function(2);
        let facts = artifact(vec![
            body(
                root,
                vec![call(0, 0, CallKindFact::TailCall, target(middle))],
            ),
            body(
                middle,
                vec![call(0, 0, CallKindFact::DirectCall, target(leaf))],
            ),
            body(leaf, Vec::new()),
        ]);

        let graph = InvocationGraph::from_artifact(&facts).expect("invocation graph");
        let leaf_id = graph.function(leaf).expect("leaf function");
        let middle_id = graph.function(middle).expect("middle function");
        let leaf_call = graph.incoming_invocations(leaf_id)[0];
        let invocation = graph.invocation(leaf_call);

        assert_eq!(graph.caller(leaf_call), middle_id);
        assert_eq!(invocation.id(), leaf_call);
        assert_eq!(invocation.caller(), middle_id);
        assert_eq!(invocation.raw_calls(), &[CallId::new(0)]);
        assert_eq!(graph.stable_function(leaf_id), leaf);
        assert_eq!(graph.incoming_invocations(middle_id).len(), 1);
    }

    #[test]
    fn unresolved_callable_matrix_keeps_declarations_and_unrelated_calls_isolated() {
        let caller = stable_function(0);
        let unrelated_owner = stable_function(1);
        let unrelated_callees = [stable_function(2), stable_function(4)];
        let trait_method = stable_function(3);
        let mut pointer_call = call(
            0,
            7,
            CallKindFact::IndirectCall,
            CallTargetFact::OpaqueBoundary {
                description: String::from("unresolved function pointer"),
                target: None,
            },
        );
        pointer_call.indirect_kind = Some(IndirectCallKindFact::FunctionPointer);
        let mut dynamic_call = call(
            1,
            8,
            CallKindFact::IndirectCall,
            opaque_trait_declaration(trait_method, "unresolved dynamic dispatch"),
        );
        dynamic_call.indirect_kind = Some(IndirectCallKindFact::DynamicDispatch);
        let facts = artifact(vec![
            body(caller, vec![pointer_call, dynamic_call]),
            body(
                unrelated_owner,
                vec![
                    call(0, 9, CallKindFact::DirectCall, target(unrelated_callees[0])),
                    call(
                        1,
                        10,
                        CallKindFact::DirectCall,
                        target(unrelated_callees[1]),
                    ),
                ],
            ),
            body(unrelated_callees[0], Vec::new()),
            body(trait_method, Vec::new()),
            body(unrelated_callees[1], Vec::new()),
        ]);

        let graph = InvocationGraph::from_artifact(&facts).expect("invocation graph");
        let pointer_call = graph
            .invocation_for_raw_call(caller, CallId::new(0))
            .unwrap();
        let dyn_call = graph
            .invocation_for_raw_call(caller, CallId::new(1))
            .unwrap();

        assert_ne!(pointer_call, dyn_call);
        for (invocation, reason) in [
            (pointer_call, UnresolvedCallTargetReason::FunctionPointer),
            (dyn_call, UnresolvedCallTargetReason::DynamicDispatch),
        ] {
            assert_eq!(
                graph.invocation(invocation).targets,
                vec![CallTarget::Unknown]
            );
            assert_eq!(
                graph.invocation(invocation).resolution(),
                InvocationResolution::Unresolved { reason }
            );
        }
        assert!(
            graph
                .invocation(pointer_call)
                .declaration_targets()
                .next()
                .is_none(),
            "a function pointer has no declaration surface"
        );
        assert_eq!(
            graph
                .invocation(dyn_call)
                .declaration_targets()
                .collect::<Vec<_>>(),
            vec![graph.function(trait_method).unwrap()]
        );
        let trait_method = graph.function(trait_method).unwrap();
        assert!(
            graph.incoming_invocations(trait_method).is_empty(),
            "a declaration is not an implementation edge for PanicEffect or SafetyEffect"
        );
        assert_eq!(
            graph.comment_graph().incoming_invocations(trait_method),
            &[dyn_call],
            "CommentEffect may propagate the declaration's surface contract"
        );
        for unrelated_target in unrelated_callees {
            let target = graph.function(unrelated_target).unwrap();
            let [invocation] = graph.incoming_invocations(target) else {
                panic!("the unrelated direct call must remain local to its own caller")
            };
            assert_eq!(
                graph.caller(*invocation),
                graph.function(unrelated_owner).unwrap()
            );
        }
    }

    #[test]
    fn standalone_declaration_target_is_comment_only_graph_edge() {
        let caller = stable_function(0);
        let declaration = stable_function(1);
        let mut unresolved_call = call(
            0,
            7,
            CallKindFact::IndirectCall,
            CallTargetFact::OpaqueBoundary {
                description: String::from("unresolved generic dispatch"),
                target: None,
            },
        );
        let CallTargetFact::Function(declaration_target) = target(declaration) else {
            unreachable!("target helper always creates a function target")
        };
        unresolved_call.declaration_target = Some(declaration_target);
        let facts = artifact(vec![body(caller, vec![unresolved_call])]);

        let graph = InvocationGraph::from_artifact(&facts).expect("invocation graph");
        let invocation = graph
            .invocation_for_raw_call(caller, CallId::new(0))
            .expect("unresolved invocation");
        let declaration = graph
            .function(declaration)
            .expect("standalone declaration graph node");

        assert_eq!(
            graph
                .invocation(invocation)
                .declaration_targets()
                .collect::<Vec<_>>(),
            vec![declaration]
        );
        assert!(
            graph.incoming_invocations(declaration).is_empty(),
            "a declaration is not a PanicEffect or SafetyEffect target"
        );
        assert_eq!(
            graph.comment_graph().incoming_invocations(declaration),
            &[invocation],
            "CommentEffect may propagate the standalone declaration contract"
        );
    }

    #[test]
    fn const_and_coroutine_bodies_are_transparent_not_invocations() {
        let owner = stable_function(0);
        let inline_const = stable_function(1);
        let coroutine = stable_function(2);
        let facts = artifact(vec![
            body(
                owner,
                vec![
                    call(0, 0, CallKindFact::ConstBody, target(inline_const)),
                    call(1, 1, CallKindFact::CoroutineBody, target(coroutine)),
                ],
            ),
            body(inline_const, Vec::new()),
            body(coroutine, Vec::new()),
        ]);

        let graph = InvocationGraph::from_artifact(&facts).expect("invocation graph");
        for child in [inline_const, coroutine] {
            let child = graph.function(child).unwrap();
            let [edge] = graph.transparent_parents(child) else {
                panic!("expected one transparent parent")
            };
            assert_eq!(
                graph.transparent_parent(*edge),
                graph.function(owner).unwrap()
            );
            assert!(graph.incoming_invocations(child).is_empty());
        }
    }

    #[test]
    fn macro_edges_do_not_propagate_and_call_macro_frames_remain_provenance() {
        let caller = stable_function(0);
        let invoked_function = stable_function(1);
        let macro_definition = stable_function(3).def_path_hash;
        let mut invoked = call(0, 0, CallKindFact::DirectCall, target(invoked_function));
        invoked.macro_expansions.push(MacroExpansionFact {
            macro_def: macro_definition,
            display_path: String::from("sample::wrapper"),
            source_range: None,
        });
        let facts = artifact(vec![
            body(caller, vec![invoked]),
            body(invoked_function, Vec::new()),
        ]);

        let graph = InvocationGraph::from_artifact(&facts).expect("invocation graph");
        let invocation = graph.incoming_invocations(graph.function(invoked_function).unwrap())[0];

        assert_eq!(graph.invocation(invocation).macro_provenance().len(), 1);
    }

    #[test]
    fn macro_provenance_groups_by_stable_identity_not_display_path() {
        let caller = stable_function(0);
        let first = stable_function(1);
        let second = stable_function(2);
        let macro_definition = stable_function(3).def_path_hash;
        let mut first_call = call(0, 7, CallKindFact::DirectCall, target(first));
        first_call.macro_expansions.push(MacroExpansionFact {
            macro_def: macro_definition,
            display_path: String::from("core::wrapper"),
            source_range: None,
        });
        let mut second_call = call(1, 7, CallKindFact::DirectCall, target(second));
        second_call.macro_expansions.push(MacroExpansionFact {
            macro_def: macro_definition,
            display_path: String::from("core::dependency::reexport::core::wrapper"),
            source_range: None,
        });
        let facts = artifact(vec![
            body(caller, vec![first_call, second_call]),
            body(first, Vec::new()),
            body(second, Vec::new()),
        ]);

        let graph = InvocationGraph::from_artifact(&facts)
            .expect("presentation-only macro path differences must not split an invocation");
        let invocation = graph
            .invocation_for_raw_call(caller, CallId::new(0))
            .expect("first raw call should belong to an invocation");

        assert_eq!(
            graph.invocation_for_raw_call(caller, CallId::new(1)),
            Some(invocation)
        );
        assert_eq!(graph.invocation(invocation).targets.len(), 2);
    }

    fn grouped_macro_panic_termination(exact_macro_call: u32) -> Option<PanicTermination> {
        let caller = stable_function(0);
        let panicking = stable_function(1);
        let sibling = stable_function(2);
        let macro_definition = stable_function(3).def_path_hash;
        let macro_path = |call| {
            if call == exact_macro_call {
                "core::ub_checks::assert_unsafe_precondition"
            } else {
                "core::ub_checks::precondition_alias"
            }
        };
        let mut panicking_call = call(0, 7, CallKindFact::DirectCall, target(panicking));
        panicking_call.macro_expansions.push(MacroExpansionFact {
            macro_def: macro_definition,
            display_path: macro_path(0).to_owned(),
            source_range: None,
        });
        let mut sibling_call = call(1, 7, CallKindFact::DirectCall, target(sibling));
        sibling_call.macro_expansions.push(MacroExpansionFact {
            macro_def: macro_definition,
            display_path: macro_path(1).to_owned(),
            source_range: None,
        });
        let mut panicking_body = body(panicking, Vec::new());
        panicking_body.effects.push(EffectFact {
            id: EffectId::new(0),
            safety_effect_group: None,
            source_range: None,
            expanded_range: None,
            macro_expansions: Vec::new(),
            kind: EffectFactKind::CompilerAssert {
                kind: CompilerAssertKind::BoundsCheck,
            },
        });
        let facts = artifact(vec![
            body(caller, vec![panicking_call, sibling_call]),
            panicking_body,
            body(sibling, Vec::new()),
        ]);
        let graph = InvocationGraph::from_artifact(&facts).expect("invocation graph");
        let annotations = AnnotationIndex::from_artifact(&facts, &graph).expect("annotation index");
        let namespaces = facts.definition_namespace_index();
        let panic = PanicEffect::probe(
            &facts,
            &graph,
            &annotations,
            &namespaces,
            &PanicConfig::default(),
        )
        .expect("panic effect");
        let trace = EffectEngine::new(&graph).trace(&panic);

        trace.handled().next().map(|handled| *handled.termination())
    }

    #[test]
    fn grouped_macro_panic_termination_is_independent_of_raw_call_id() {
        assert_eq!(
            grouped_macro_panic_termination(0),
            Some(PanicTermination::IgnoredBoundary)
        );
        assert_eq!(
            grouped_macro_panic_termination(1),
            Some(PanicTermination::IgnoredBoundary)
        );
    }

    #[test]
    fn exact_function_instances_keep_their_incoming_invocations_separate() {
        let generic = stable_function(0);
        let first = exact_function(generic, 1);
        let second = exact_function(generic, 2);
        let first_caller = stable_function(3);
        let second_caller = stable_function(4);
        let facts = artifact(vec![
            body(
                first_caller,
                vec![call(0, 0, CallKindFact::DirectCall, target(first))],
            ),
            body(
                second_caller,
                vec![call(0, 0, CallKindFact::DirectCall, target(second))],
            ),
            body(first, Vec::new()),
            body(second, Vec::new()),
        ]);

        let graph = InvocationGraph::from_artifact(&facts).expect("invocation graph");
        let first_incoming = graph.incoming_invocations(graph.function(first).unwrap());
        let second_incoming = graph.incoming_invocations(graph.function(second).unwrap());

        assert_eq!(first_incoming.len(), 1);
        assert_eq!(second_incoming.len(), 1);
        assert_eq!(
            graph.stable_function(graph.caller(first_incoming[0])),
            first_caller
        );
        assert_eq!(
            graph.stable_function(graph.caller(second_incoming[0])),
            second_caller
        );
    }

    #[test]
    fn exact_target_falls_back_to_its_available_generic_body() {
        let caller = stable_function(0);
        let generic_callee = stable_function(1);
        let exact_callee = exact_function(generic_callee, 2);
        let facts = artifact(vec![
            body(
                caller,
                vec![call(0, 0, CallKindFact::DirectCall, target(exact_callee))],
            ),
            body(generic_callee, Vec::new()),
        ]);

        let graph = InvocationGraph::from_artifact(&facts).expect("invocation graph");
        let generic_incoming = graph.incoming_invocations(graph.function(generic_callee).unwrap());

        assert_eq!(generic_incoming.len(), 1);
        assert_eq!(
            graph.stable_function(graph.caller(generic_incoming[0])),
            caller
        );
    }

    #[test]
    fn resolved_exact_projection_does_not_hide_unresolved_sibling() {
        let generic_caller = stable_function(0);
        let resolved_caller = exact_function(generic_caller, 1);
        let unresolved_caller = exact_function(generic_caller, 2);
        let callee = stable_function(3);
        let facts = artifact(vec![
            body(
                resolved_caller,
                vec![call(0, 7, CallKindFact::DirectCall, target(callee))],
            ),
            body(
                unresolved_caller,
                vec![call(0, 7, CallKindFact::IndirectCall, opaque())],
            ),
            body(callee, Vec::new()),
        ]);

        let graph = InvocationGraph::from_artifact(&facts).expect("invocation graph");
        let unresolved = graph
            .invocation_for_raw_call(unresolved_caller, CallId::new(0))
            .expect("unresolved invocation");

        assert!(graph.invocation(unresolved).is_unresolved());
    }

    #[test]
    fn source_calls_without_ranges_remain_distinct_by_call_site() {
        let source_owner = stable_function(0);
        let destination = stable_function(1);
        let facts = artifact(vec![
            body(
                source_owner,
                vec![
                    call(0, 7, CallKindFact::DirectCall, target(destination)),
                    call(1, 8, CallKindFact::IndirectCall, opaque()),
                ],
            ),
            body(destination, Vec::new()),
        ]);

        let graph = InvocationGraph::from_artifact(&facts).expect("invocation graph");
        let resolved = graph
            .invocation_for_raw_call(source_owner, CallId::new(0))
            .expect("resolved invocation");
        let unresolved = graph
            .invocation_for_raw_call(source_owner, CallId::new(1))
            .expect("unresolved invocation");

        assert_eq!(graph.invocation_aliases(resolved), vec![resolved]);
        assert_eq!(graph.invocation_aliases(unresolved), vec![unresolved]);
        assert!(graph.invocation(unresolved).is_unresolved());
    }

    #[test]
    fn source_projection_uses_ranges_across_artifact_local_call_site_ids() {
        let generic_caller = stable_function(0);
        let exact_caller = exact_function(generic_caller, 1);
        let callee = stable_function(2);
        let mut defining_call = call(0, 7, CallKindFact::IndirectCall, opaque());
        defining_call.source_range = Some(source_range(10, 20));
        defining_call.expanded_range = Some(source_range(10, 20));
        let mut unrelated_call = call(0, 98, CallKindFact::DirectCall, target(callee));
        unrelated_call.source_range = Some(source_range(1, 2));
        unrelated_call.expanded_range = Some(source_range(1, 2));
        let mut consumer_call = call(1, 99, CallKindFact::DirectCall, target(callee));
        consumer_call.source_range = Some(source_range(10, 20));
        consumer_call.expanded_range = Some(source_range(10, 20));
        let facts = ArtifactFacts::new(
            vec![
                body(generic_caller, vec![defining_call]),
                body(exact_caller, vec![unrelated_call, consumer_call]),
                body(callee, Vec::new()),
            ],
            vec![source_file()],
        )
        .expect("valid direct artifact facts");

        let graph = InvocationGraph::from_artifact(&facts).expect("invocation graph");
        let defining = graph
            .invocation_for_raw_call(generic_caller, CallId::new(0))
            .expect("defining invocation");
        let consumer = graph
            .invocation_for_raw_call(exact_caller, CallId::new(1))
            .expect("consumer invocation");

        assert_eq!(graph.invocation_aliases(defining), vec![defining, consumer]);
        assert_eq!(
            graph.projected_raw_call(defining, CallId::new(0), consumer),
            Some(CallId::new(1)),
            "body-local call IDs must be projected by source identity"
        );
        assert!(graph.invocation(defining).is_unresolved());
        assert!(!graph.invocation(consumer).is_unresolved());
    }

    #[test]
    fn implementation_contract_fallback_is_single_and_definition_level() {
        let generic_implementation = stable_function(0);
        let exact_implementation = exact_function(generic_implementation, 1);
        let declaration = stable_function(2);
        let exact_caller = stable_function(3);
        let facts = artifact(vec![
            body(
                exact_caller,
                vec![call(
                    0,
                    7,
                    CallKindFact::DirectCall,
                    target(exact_implementation),
                )],
            ),
            body_with_contract_declaration(generic_implementation, declaration),
        ]);

        let graph = InvocationGraph::from_artifact(&facts).expect("invocation graph");

        for implementation in [generic_implementation, exact_implementation] {
            let implementation = graph
                .function(implementation)
                .expect("implementation graph identity");
            assert_eq!(
                graph.contract_declaration(implementation),
                Some(declaration)
            );
        }
        assert!(graph.function(declaration).is_some());

        let conflicting_implementation = stable_function(4);
        let other_declaration = stable_function(5);
        let mut implementation_call = call(
            0,
            7,
            CallKindFact::DirectCall,
            target(conflicting_implementation),
        );
        let CallTargetFact::Function(other_declaration_target) = target(other_declaration) else {
            unreachable!("target helper always creates a function target")
        };
        implementation_call.declaration_target = Some(other_declaration_target);
        let conflicting_facts = artifact(vec![
            body(exact_caller, vec![implementation_call]),
            body_with_contract_declaration(conflicting_implementation, declaration),
        ]);

        let Err(error) = InvocationGraph::from_artifact(&conflicting_facts) else {
            panic!("one implementation cannot have two contract declarations");
        };

        assert!(
            error
                .to_string()
                .contains("has conflicting contract declarations"),
            "unexpected graph error: {error}"
        );
    }

    #[test]
    fn source_invocation_retains_distinct_desugared_declarations() {
        let caller = stable_function(0);
        let first_declaration = stable_function(1);
        let second_declaration = stable_function(2);
        let facts = artifact(vec![
            body(
                caller,
                vec![
                    call(
                        0,
                        7,
                        CallKindFact::IndirectCall,
                        opaque_trait_declaration(first_declaration, "for-loop desugaring"),
                    ),
                    call(
                        1,
                        7,
                        CallKindFact::IndirectCall,
                        opaque_trait_declaration(first_declaration, "for-loop desugaring"),
                    ),
                    call(
                        2,
                        7,
                        CallKindFact::IndirectCall,
                        opaque_trait_declaration(second_declaration, "for-loop desugaring"),
                    ),
                ],
            ),
            body(first_declaration, Vec::new()),
            body(second_declaration, Vec::new()),
        ]);

        let graph = InvocationGraph::from_artifact(&facts)
            .expect("one desugared source site may contain several declaration calls");
        let invocation = graph
            .invocation_for_raw_call(caller, CallId::new(0))
            .expect("grouped invocation");
        assert_eq!(
            graph.invocation_for_raw_call(caller, CallId::new(1)),
            Some(invocation),
            "duplicate projections share the source invocation"
        );
        assert_eq!(
            graph.invocation_for_raw_call(caller, CallId::new(2)),
            Some(invocation),
            "distinct desugared declarations share the source invocation"
        );
        let mut expected = vec![
            graph.function(first_declaration).unwrap(),
            graph.function(second_declaration).unwrap(),
        ];
        expected.sort();

        assert_eq!(
            graph
                .invocation(invocation)
                .declaration_targets()
                .collect::<Vec<_>>(),
            expected
        );
    }
}
