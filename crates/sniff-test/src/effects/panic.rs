use std::collections::{BTreeMap, BTreeSet};

use effect_tracing::{
    EffectSeed, FunctionId, InvocationId, Propagation, PropagationEdge, TraceCx, TracePolicy,
    TraceSite,
};

use crate::annotations::{AnnotationDomain, AnnotationId, AnnotationIndex, SiteCommentAnnotation};
use crate::artifact::{
    ArtifactFacts, CallFact, CallId, CompilerAssertKind, DefinitionNamespaceIndex, EffectFactKind,
    EffectId, FunctionId as StableFunctionId, FunctionTargetFact,
};
use crate::compiler::invocations::InvocationGraph;
use crate::compiler::{effect_passes::EffectPassRegistry, panic::CompilerAssertPass};
use crate::config::{PanicBoundaryPolicy, PanicConfig};

use super::obligation::ConcreteState;
use super::trust::TrustPath;
use super::{InvocationSourceBranch, ProbeError};

pub(crate) struct Panic;

impl super::Effect for Panic {
    const EFFECT_NAME: &'static str = "panic";
    const OBLIGATION: &'static str = "Panics";
    const JUSTIFICATION: &'static str = "PANIC";

    fn register_passes(registry: &mut EffectPassRegistry) {
        registry.register_mir_pass(Box::new(CompilerAssertPass));
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum PanicOrigin {
    Invocation {
        invocation: InvocationId,
        call: CallId,
    },
    CompilerAssert {
        owner: StableFunctionId,
        effect: EffectId,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum PanicKind {
    Invocation,
    CompilerAssert(CompilerAssertKind),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct PanicState {
    kind: PanicKind,
    current_function: FunctionId,
    invocation_justification: Option<AnnotationId>,
    trust_path: TrustPath,
}

impl PanicState {
    #[must_use]
    pub(crate) fn trust_path(&self) -> &TrustPath {
        &self.trust_path
    }

    pub(crate) const fn kind(&self) -> PanicKind {
        self.kind
    }
}

impl ConcreteState for PanicState {
    fn current_function(&self) -> FunctionId {
        self.current_function
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum PanicTermination {
    Justification(AnnotationId),
    TrustedBoundary,
    IgnoredBoundary,
}

pub(crate) struct PanicEffect<'annotations> {
    annotations: &'annotations AnnotationIndex,
    graph: &'annotations InvocationGraph,
    seeds: Vec<EffectSeed<PanicOrigin, PanicState>>,
    trusted_functions: BTreeSet<FunctionId>,
    ignored_functions: BTreeSet<FunctionId>,
    macro_ignored_sources: BTreeSet<PanicOrigin>,
    macro_ignored_invocations: BTreeSet<InvocationId>,
    invocation_sources: BTreeMap<InvocationId, Vec<InvocationSourceBranch>>,
}

impl<'annotations> PanicEffect<'annotations> {
    #[allow(
        clippy::too_many_lines,
        reason = "panic probing remains effect-specific instead of introducing a compiler visitor registry"
    )]
    pub(crate) fn probe(
        artifact: &ArtifactFacts,
        graph: &'annotations InvocationGraph,
        annotations: &'annotations AnnotationIndex,
        namespaces: &DefinitionNamespaceIndex,
        config: &PanicConfig,
    ) -> Result<Self, ProbeError> {
        let mut seeds = Vec::new();
        let mut trusted_functions = BTreeSet::new();
        let mut ignored_functions = BTreeSet::new();
        let mut macro_ignored_sources = BTreeSet::new();
        for body in &artifact.functions {
            let candidates = namespaces.candidates(body.function);
            if config.ignores_candidates(candidates) {
                ignored_functions.extend(graph.function_aliases(body.function));
                continue;
            }
            let owner = graph.function(body.function).ok_or_else(|| {
                ProbeError::new(format!(
                    "panic source owner {:?} is missing from the invocation graph",
                    body.function
                ))
            })?;
            if config.panic_boundary_policy_candidates(candidates)
                == PanicBoundaryPolicy::TrustedBoundary
            {
                trusted_functions.extend(graph.function_aliases(body.function));
            }
            for effect in &body.effects {
                if let EffectFactKind::CompilerAssert { kind } = effect.kind {
                    let origin = PanicOrigin::CompilerAssert {
                        owner: body.function,
                        effect: effect.id,
                    };
                    if effect
                        .macro_expansions
                        .iter()
                        .any(|frame| config.ignores_path(&frame.display_path))
                    {
                        macro_ignored_sources.insert(origin);
                    }
                    seeds.push(EffectSeed::new(
                        origin,
                        owner,
                        PanicState {
                            kind: PanicKind::CompilerAssert(kind),
                            current_function: owner,
                            invocation_justification: None,
                            trust_path: TrustPath::new(graph, owner),
                        },
                    ));
                }
            }
        }
        let macro_ignored_invocations = graph
            .invocations()
            .filter(|invocation| {
                invocation
                    .macro_provenance()
                    .iter()
                    .any(|frame| config.ignores_path(&frame.display_path))
            })
            .map(crate::compiler::invocations::Invocation::id)
            .collect::<BTreeSet<_>>();

        let mut invocation_sources = BTreeMap::<InvocationId, Vec<InvocationSourceBranch>>::new();
        for body in &artifact.functions {
            if config.ignores_candidates(namespaces.candidates(body.function)) {
                continue;
            }
            for call in &body.calls {
                let Some(target) = panic_sink_target(call, namespaces, config) else {
                    continue;
                };
                if let Some(invocation) = graph.invocation_for_raw_call(body.function, call.id) {
                    invocation_sources.entry(invocation).or_default().push(
                        InvocationSourceBranch::new(call.clone(), Some(target.clone())),
                    );
                }
            }
        }
        for (&invocation, sources) in &invocation_sources {
            for source in sources {
                let origin = PanicOrigin::Invocation {
                    invocation,
                    call: source.edge().id,
                };
                if source
                    .edge()
                    .macro_expansions
                    .iter()
                    .any(|frame| config.ignores_path(&frame.display_path))
                {
                    macro_ignored_sources.insert(origin);
                }
                seeds.push(EffectSeed::new(
                    origin,
                    graph.invocation(invocation).caller(),
                    PanicState {
                        kind: PanicKind::Invocation,
                        current_function: graph.invocation(invocation).caller(),
                        invocation_justification: None,
                        trust_path: TrustPath::new(graph, graph.invocation(invocation).caller()),
                    },
                ));
            }
        }
        for seed in &mut seeds {
            if trusted_functions.contains(&seed.owner) {
                seed.state.trust_path = TrustPath::default();
            }
        }
        Ok(Self {
            annotations,
            graph,
            seeds,
            trusted_functions,
            ignored_functions,
            macro_ignored_sources,
            macro_ignored_invocations,
            invocation_sources,
        })
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) fn source_count(&self) -> usize {
        self.seeds.len()
    }

    pub(crate) fn is_opaque_on_path(&self, function: FunctionId, path: &TrustPath) -> bool {
        self.ignored_functions.contains(&function)
            || (self.is_trusted_function(function) && path.allows_boundary(self.graph, function))
    }

    #[must_use]
    pub(crate) fn is_trusted_function(&self, function: FunctionId) -> bool {
        self.trusted_functions.contains(&function)
    }

    #[must_use]
    pub(crate) fn is_ignored_invocation(&self, invocation: InvocationId) -> bool {
        self.macro_ignored_invocations.contains(&invocation)
    }

    #[must_use]
    pub(crate) fn invocation_sources(&self, invocation: InvocationId) -> &[InvocationSourceBranch] {
        self.invocation_sources
            .get(&invocation)
            .map_or(&[], Vec::as_slice)
    }

    #[must_use]
    pub(crate) fn invocation_source(
        &self,
        invocation: InvocationId,
        call: CallId,
    ) -> Option<&InvocationSourceBranch> {
        self.invocation_sources(invocation)
            .iter()
            .find(|source| source.edge().id == call)
    }

    fn source_justification(&self, origin: PanicOrigin) -> Option<AnnotationId> {
        match origin {
            PanicOrigin::Invocation { invocation, call } => {
                self.raw_call_justification(invocation, call)
            }
            PanicOrigin::CompilerAssert { owner, effect } => self
                .annotations
                .comments_at_effect(owner, effect, AnnotationDomain::Panic)
                .find(|comment| comment.has_justification())
                .map(SiteCommentAnnotation::id),
        }
    }

    fn invocation_justification(
        &self,
        invocation: InvocationId,
        target: FunctionId,
    ) -> Option<AnnotationId> {
        let mut calls = self.graph.raw_calls_reaching(invocation, target);
        let selected = self.raw_call_justification(invocation, calls.next()?)?;
        for call in calls {
            self.raw_call_justification(invocation, call)?;
        }
        Some(selected)
    }

    fn raw_call_justification(
        &self,
        invocation: InvocationId,
        call: CallId,
    ) -> Option<AnnotationId> {
        self.annotations
            .comments_at_raw_call(invocation, call, AnnotationDomain::Panic)
            .find(|comment| comment.has_justification())
            .map(SiteCommentAnnotation::id)
    }
}

fn panic_sink_target<'call>(
    call: &'call CallFact,
    namespaces: &DefinitionNamespaceIndex,
    config: &PanicConfig,
) -> Option<&'call FunctionTargetFact> {
    call.target
        .function_target()
        .filter(|target| {
            config.panic_boundary_policy_candidates(namespaces.candidates(target.function))
                == PanicBoundaryPolicy::PanicSink
        })
        .or_else(|| {
            call.declaration_target.as_ref().filter(|target| {
                config.panic_boundary_policy_candidates(namespaces.candidates(target.function))
                    == PanicBoundaryPolicy::PanicSink
            })
        })
}

impl TracePolicy for PanicEffect<'_> {
    type Origin = PanicOrigin;
    type State = PanicState;
    type Termination = PanicTermination;

    fn sources(&self) -> impl Iterator<Item = EffectSeed<Self::Origin, Self::State>> + '_ {
        self.seeds.iter().cloned()
    }

    fn propagate(
        &self,
        cx: &TraceCx<'_>,
        state: &Self::State,
        edge: PropagationEdge,
    ) -> Propagation<Self::State> {
        let mut next = state.clone();
        next.invocation_justification = None;
        next.current_function = match edge {
            PropagationEdge::Invocation(invocation) => {
                next.invocation_justification =
                    self.invocation_justification(invocation, state.current_function);
                self.graph.invocation(invocation).caller()
            }
            PropagationEdge::TransparentBody(edge) => cx.graph().transparent_parent(edge),
            PropagationEdge::ContractHandoff => {
                unreachable!("contract handoffs are created by the tracing engine")
            }
        };
        if !self.is_trusted_function(next.current_function) {
            next.trust_path.enter(self.graph, next.current_function);
        }
        Propagation::Follow(next)
    }

    fn terminate(
        &self,
        _cx: &TraceCx<'_>,
        state: &Self::State,
        site: TraceSite<'_, Self::Origin>,
    ) -> Option<Self::Termination> {
        match site {
            TraceSite::Source(origin) => {
                if self.macro_ignored_sources.contains(origin) {
                    Some(PanicTermination::IgnoredBoundary)
                } else {
                    self.source_justification(*origin)
                        .map(PanicTermination::Justification)
                }
            }
            TraceSite::Function(function) => {
                if self.ignored_functions.contains(&function) {
                    Some(PanicTermination::IgnoredBoundary)
                } else {
                    (self.trusted_functions.contains(&function)
                        && state.trust_path.allows_boundary(self.graph, function))
                    .then_some(PanicTermination::TrustedBoundary)
                }
            }
            TraceSite::Invocation(invocation) => {
                if self.macro_ignored_invocations.contains(&invocation) {
                    Some(PanicTermination::IgnoredBoundary)
                } else {
                    state
                        .invocation_justification
                        .map(PanicTermination::Justification)
                }
            }
        }
    }
}
