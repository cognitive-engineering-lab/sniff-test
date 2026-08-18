//! Permanent typed compiler-assert evaluation and owned report projection.
//!
//! Compiler assertions are prepared from the exact typed workspace closure.
//! The legacy interpreter remains a separate consumer for panic calls, safety,
//! ambiguity, and completeness; none of its compiler-assert witnesses enter
//! this module.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::analysis::cache::{ArtifactAnalysisCache, RustcArtifactId};
use crate::analysis::facts::collection::CollectedArtifactSchemaPack;
use crate::analysis::facts::composition::graph::WorkspaceRelationError;
use crate::analysis::facts::composition::{
    CompositionBuildError, CompositionRelationBuilder, WorkspaceEvaluationView,
    WorkspaceRelationIndex,
};
use crate::analysis::facts::encoded::{ArtifactFactIr, RowRef};
use crate::analysis::facts::evaluation::{
    EvaluationDb, EvaluationPipelineError, EvaluationRoot, EvaluationStorageError,
    TypedEvaluatedIssue,
};
use crate::analysis::facts::human::HumanEvidencePack;
use crate::analysis::facts::pack::{AnalysisRegistry, PackRegistrationError};
use crate::analysis::facts::panic::model::UnsatisfiedCompilerAssertIssue;
use crate::analysis::facts::panic::rules::PanicPack;
use crate::analysis::facts::panic::{
    CompilerAssertInputError, CompilerAssertInputPack, CompilerAssertRootInputs,
    CompilerAssertRootRequest, CompilerAssertSemanticEdge, CompilerAssertSemanticTrace,
    CompilerAssertSemanticTraceStep, CompilerAssertTraceError, CompilerAssertTraceProjector,
    PreparedCompilerAssertRootBatch, compiler_assert_presentation,
};
use crate::analysis::facts::program::root_traversal::MarkerProbe;
use crate::analysis::facts::program::topology::{CallAttributionRole, CallKind};
use crate::analysis::facts::program::{
    FunctionHasSourceAnchor, FunctionKey, SourceAnchorKey, SourceFileEntity,
};
use crate::analysis::facts::render::{RenderCx, RenderError, RenderedDiagnostic};
use crate::analysis::facts::view::{ArtifactDbView, ViewError};
use crate::analysis::facts::workspace::{
    ArtifactScopeId, ArtifactScopeIdError, ScopedEntityRef, WorkspaceFactView, WorkspaceViewError,
};
use crate::analysis::graph::ArtifactAnalysisGraph;
use crate::analysis::interpret::InterpretationRoot;
use crate::analysis::ir::{FunctionId, SourceFileId, SourceFileIr, SourceRangeIr};
use crate::analysis::workspace_closure::{
    ManagedArtifactGeneration, ManagedArtifactManifest, VerifiedWorkspaceClosure,
    VerifiedWorkspaceClosureError,
};
use crate::config::{CallableEdgeAttribution, MarkerProbing, SniffTestConfig};
use crate::panics::CompilerAssertKind;
use crate::report_roots::ReportRootKind;

/// One local typed artifact generation.
#[derive(Clone, Copy)]
pub(crate) struct TypedPanicLocalArtifact<'a> {
    facts: &'a ArtifactFactIr,
    identity: LocalArtifactIdentity<'a>,
}

#[derive(Clone, Copy)]
enum LocalArtifactIdentity<'a> {
    Persisted(&'a RustcArtifactId),
    InMemory { stable_crate_id: u64 },
}

impl<'a> TypedPanicLocalArtifact<'a> {
    #[must_use]
    pub(crate) const fn in_memory(facts: &'a ArtifactFactIr, stable_crate_id: u64) -> Self {
        Self {
            facts,
            identity: LocalArtifactIdentity::InMemory { stable_crate_id },
        }
    }

    #[must_use]
    pub(crate) const fn persisted(
        facts: &'a ArtifactFactIr,
        artifact: &'a RustcArtifactId,
    ) -> Self {
        Self {
            facts,
            identity: LocalArtifactIdentity::Persisted(artifact),
        }
    }

    fn generation(self) -> ManagedArtifactGeneration {
        match self.identity {
            LocalArtifactIdentity::Persisted(artifact) => {
                ManagedArtifactGeneration::persisted(artifact.clone())
            }
            LocalArtifactIdentity::InMemory { stable_crate_id } => {
                ManagedArtifactGeneration::in_memory(stable_crate_id, 0)
            }
        }
    }
}

/// Structured failure from permanent compiler-assert evaluation or reporting.
#[derive(Debug)]
pub(super) enum TypedPanicEvaluationError {
    Registration(Box<PackRegistrationError>),
    ArtifactScope {
        artifact: String,
        source: Box<ArtifactScopeIdError>,
    },
    ArtifactView {
        scope: ArtifactScopeId,
        source: Box<ViewError>,
    },
    Workspace(Box<WorkspaceViewError>),
    Closure(Box<VerifiedWorkspaceClosureError>),
    Input(Box<CompilerAssertInputError>),
    Composition(Box<CompositionBuildError>),
    Relations(Box<WorkspaceRelationError>),
    Evaluation(Box<EvaluationPipelineError>),
    Results(Box<EvaluationStorageError>),
    Trace(Box<CompilerAssertTraceError>),
    Render(Box<RenderError>),
    MissingRenderContext {
        scope: ArtifactScopeId,
    },
    PreparedRootCount {
        expected: usize,
        actual: usize,
    },
    MultiplePresentationAnchors {
        endpoint: ScopedEntityRef,
    },
    ConflictingSourceFileIdentity {
        file: SourceFileId,
    },
    InvalidSemanticTraceProjection {
        issue: RowRef,
        reason: String,
    },
}

/// Owned compiler-assert report for one requested root.
#[derive(Clone, Debug)]
pub(super) struct TypedPanicRootReport {
    pub(super) root: EvaluationRoot,
    pub(super) function: FunctionId,
    pub(super) path: String,
    pub(super) kind: ReportRootKind,
    pub(super) presentation_range: Option<SourceRangeIr>,
    pub(super) issues: Vec<TypedPanicIssueReport>,
}

#[derive(Clone, Debug)]
pub(super) struct TypedPanicBatchReport {
    pub(super) roots: Vec<TypedPanicRootReport>,
    pub(super) source_files: Vec<SourceFileIr>,
}

#[derive(Clone, Debug)]
pub(super) struct TypedPanicIssueReport {
    pub(super) issue: TypedEvaluatedIssue<UnsatisfiedCompilerAssertIssue>,
    pub(super) compiler_assert_kind: CompilerAssertKind,
    pub(super) reason: String,
    pub(super) target: String,
    pub(super) diagnostic: RenderedDiagnostic,
    pub(super) presentation_range: Option<SourceRangeIr>,
    pub(super) trace: CompilerAssertSemanticTrace,
}

type RootTypedPanicEvaluation = Result<TypedPanicRootReport, TypedPanicEvaluationError>;

struct PreparedTypedPanicWorkspace<'a, 'facts> {
    registry: &'a AnalysisRegistry<CompilerAssertRootInputs>,
    workspace: &'a WorkspaceFactView<'facts>,
    render_contexts: &'a BTreeMap<ArtifactScopeId, RenderCx<'facts>>,
    presentation_anchors: &'a FunctionPresentationIndex,
}

pub(super) struct OpenedTypedArtifacts<'facts> {
    pub(super) local_generation: ManagedArtifactGeneration,
    pub(super) views: Vec<(ArtifactScopeId, ArtifactDbView<'facts>)>,
    pub(super) render_contexts: BTreeMap<ArtifactScopeId, RenderCx<'facts>>,
    pub(super) dependency_manifests: Vec<ManagedArtifactManifest>,
}

#[derive(Debug)]
pub(super) struct FunctionPresentationIndex {
    by_function: BTreeMap<ScopedEntityRef, Vec<SourceRangeIr>>,
}

impl FunctionPresentationIndex {
    pub(super) fn build(
        workspace: &WorkspaceFactView<'_>,
    ) -> Result<Self, TypedPanicEvaluationError> {
        let mut by_function = BTreeMap::<ScopedEntityRef, Vec<SourceRangeIr>>::new();
        for scope in workspace.scopes() {
            let view = workspace
                .artifact(scope)
                .map_err(|source| TypedPanicEvaluationError::Workspace(Box::new(source)))?;
            for relation in view
                .relations::<FunctionHasSourceAnchor>()
                .map_err(|source| TypedPanicEvaluationError::ArtifactView {
                    scope: scope.clone(),
                    source: Box::new(source),
                })?
            {
                let anchor = view.entity(relation.to).map_err(|source| {
                    TypedPanicEvaluationError::ArtifactView {
                        scope: scope.clone(),
                        source: Box::new(source),
                    }
                })?;
                by_function
                    .entry(ScopedEntityRef::new(scope.clone(), relation.from.erase()))
                    .or_default()
                    .push(source_range(anchor.anchor()));
            }
        }
        Ok(Self { by_function })
    }

    pub(super) fn range(
        &self,
        function: &ScopedEntityRef,
    ) -> Result<Option<SourceRangeIr>, TypedPanicEvaluationError> {
        let Some(ranges) = self.by_function.get(function) else {
            return Ok(None);
        };
        match ranges.as_slice() {
            [range] => Ok(Some(range.clone())),
            [] => Ok(None),
            [_, _, ..] => Err(TypedPanicEvaluationError::MultiplePresentationAnchors {
                endpoint: function.clone(),
            }),
        }
    }
}

impl Display for TypedPanicEvaluationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registration(source) => {
                write!(
                    formatter,
                    "typed panic evaluation could not initialize: {source}"
                )
            }
            Self::ArtifactScope { artifact, source } => write!(
                formatter,
                "artifact `{artifact}` has no valid exact-generation scope: {source}"
            ),
            Self::ArtifactView { scope, source } => write!(
                formatter,
                "typed facts in artifact scope `{scope}` are invalid: {source}"
            ),
            Self::Workspace(source) => {
                write!(formatter, "typed panic workspace is invalid: {source}")
            }
            Self::Closure(source) => write!(
                formatter,
                "typed panic workspace closure is invalid: {source}"
            ),
            Self::Input(source) => write!(
                formatter,
                "compiler-assert root inputs could not be prepared: {source}"
            ),
            Self::Composition(source) => write!(
                formatter,
                "typed panic provenance cannot be composed: {source}"
            ),
            Self::Relations(source) => {
                write!(formatter, "typed panic relation graph is invalid: {source}")
            }
            Self::Evaluation(source) => {
                write!(formatter, "typed panic rules could not run: {source}")
            }
            Self::Results(source) => write!(formatter, "typed panic results are invalid: {source}"),
            Self::Trace(source) => write!(
                formatter,
                "typed panic semantic trace projection failed: {source}"
            ),
            Self::Render(source) => {
                write!(formatter, "typed panic issue rendering failed: {source}")
            }
            Self::MissingRenderContext { scope } => write!(
                formatter,
                "typed panic issue refers to unavailable artifact rendering scope `{scope}`"
            ),
            Self::PreparedRootCount { expected, actual } => write!(
                formatter,
                "compiler-assert preparation returned {actual} roots for {expected} requests"
            ),
            Self::MultiplePresentationAnchors { endpoint } => write!(
                formatter,
                "typed panic endpoint {endpoint:?} has more than one presentation source anchor"
            ),
            Self::ConflictingSourceFileIdentity { file } => write!(
                formatter,
                "typed panic workspace contains conflicting metadata for source file identity `{}`",
                file.as_str()
            ),
            Self::InvalidSemanticTraceProjection { issue, reason } => write!(
                formatter,
                "typed panic issue `{}`:{} has an invalid permanent semantic trace: {reason}",
                issue.schema, issue.row
            ),
        }
    }
}

impl Error for TypedPanicEvaluationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Registration(source) => Some(source.as_ref()),
            Self::ArtifactScope { source, .. } => Some(source.as_ref()),
            Self::ArtifactView { source, .. } => Some(source.as_ref()),
            Self::Workspace(source) => Some(source.as_ref()),
            Self::Closure(source) => Some(source.as_ref()),
            Self::Input(source) => Some(source.as_ref()),
            Self::Composition(source) => Some(source.as_ref()),
            Self::Relations(source) => Some(source.as_ref()),
            Self::Evaluation(source) => Some(source.as_ref()),
            Self::Results(source) => Some(source.as_ref()),
            Self::Trace(source) => Some(source.as_ref()),
            Self::Render(source) => Some(source.as_ref()),
            Self::MissingRenderContext { .. }
            | Self::PreparedRootCount { .. }
            | Self::MultiplePresentationAnchors { .. }
            | Self::ConflictingSourceFileIdentity { .. }
            | Self::InvalidSemanticTraceProjection { .. } => None,
        }
    }
}

/// Evaluates every requested root atomically from permanent typed facts.
pub(super) fn evaluate_typed_panic_roots(
    local: TypedPanicLocalArtifact<'_>,
    dependencies: &ArtifactAnalysisGraph,
    active_runtime_artifacts: &[RustcArtifactId],
    roots: &[InterpretationRoot],
    config: &SniffTestConfig,
) -> Result<TypedPanicBatchReport, TypedPanicEvaluationError> {
    let artifacts = dependencies.artifacts().collect::<Vec<_>>();
    evaluate_roots_with_dependencies(
        local,
        &artifacts,
        dependencies.direct_dependency_ids().collect(),
        active_runtime_artifacts,
        roots,
        config,
    )
}

#[cfg(test)]
fn evaluate_with_dependencies<'a>(
    local: TypedPanicLocalArtifact<'_>,
    dependencies: impl IntoIterator<Item = &'a ArtifactAnalysisCache>,
    active_runtime_artifacts: &[RustcArtifactId],
    root: &InterpretationRoot,
    config: &SniffTestConfig,
) -> RootTypedPanicEvaluation {
    let dependencies = dependencies.into_iter().collect::<Vec<_>>();
    let direct_dependencies = dependencies
        .iter()
        .map(|dependency| dependency.artifact.id.clone())
        .collect();
    let mut reports = evaluate_roots_with_dependencies(
        local,
        &dependencies,
        direct_dependencies,
        active_runtime_artifacts,
        std::slice::from_ref(root),
        config,
    )?
    .roots;
    Ok(reports
        .pop()
        .expect("one root request produces one typed report"))
}

pub(super) fn open_typed_artifacts<'view, C: ?Sized>(
    local: TypedPanicLocalArtifact<'view>,
    dependencies: &[&'view ArtifactAnalysisCache],
    registry: &'view AnalysisRegistry<C>,
) -> Result<OpenedTypedArtifacts<'view>, TypedPanicEvaluationError> {
    let local_generation = local.generation();
    let local_scope =
        local_generation
            .scope()
            .map_err(|source| TypedPanicEvaluationError::ArtifactScope {
                artifact: format!("{local_generation:?}"),
                source: Box::new(source),
            })?;
    let local_view = ArtifactDbView::open(local.facts, registry.schemas()).map_err(|source| {
        TypedPanicEvaluationError::ArtifactView {
            scope: local_scope.clone(),
            source: Box::new(source),
        }
    })?;
    let mut views = vec![(local_scope.clone(), local_view)];
    let mut render_contexts = BTreeMap::from([(local_scope, RenderCx::from_validated(local_view))]);
    let mut dependency_manifests = Vec::with_capacity(dependencies.len());
    for dependency in dependencies {
        let scope = canonical_persisted_scope(&dependency.artifact.id)?;
        let view =
            ArtifactDbView::open(&dependency.facts, registry.schemas()).map_err(|source| {
                TypedPanicEvaluationError::ArtifactView {
                    scope: scope.clone(),
                    source: Box::new(source),
                }
            })?;
        views.push((scope.clone(), view));
        render_contexts.insert(scope, RenderCx::from_validated(view));
        dependency_manifests.push(ManagedArtifactManifest::new(
            ManagedArtifactGeneration::persisted(dependency.artifact.id.clone()),
            dependency.dependencies.clone(),
        ));
    }
    Ok(OpenedTypedArtifacts {
        local_generation,
        views,
        render_contexts,
        dependency_manifests,
    })
}

fn evaluate_roots_with_dependencies(
    local: TypedPanicLocalArtifact<'_>,
    dependencies: &[&ArtifactAnalysisCache],
    direct_dependencies: Vec<RustcArtifactId>,
    active_runtime_artifacts: &[RustcArtifactId],
    roots: &[InterpretationRoot],
    config: &SniffTestConfig,
) -> Result<TypedPanicBatchReport, TypedPanicEvaluationError> {
    if roots.is_empty() {
        return Ok(TypedPanicBatchReport {
            roots: Vec::new(),
            source_files: Vec::new(),
        });
    }
    let registry = typed_panic_registry()
        .map_err(|source| TypedPanicEvaluationError::Registration(Box::new(source)))?;
    let opened = open_typed_artifacts(local, dependencies, &registry)?;
    let workspace = WorkspaceFactView::compose(opened.views)
        .map_err(|source| TypedPanicEvaluationError::Workspace(Box::new(source)))?;
    let source_files = permanent_source_files(&workspace)?;
    let closure = VerifiedWorkspaceClosure::open_with_runtime_inventory(
        &workspace,
        ManagedArtifactManifest::new(opened.local_generation, direct_dependencies),
        opened.dependency_manifests,
        active_runtime_artifacts.iter().cloned(),
    )
    .map_err(|source| TypedPanicEvaluationError::Closure(Box::new(source)))?;
    let requests = roots
        .iter()
        .map(|root| compiler_assert_root_request(root, config));
    let batch = PreparedCompilerAssertRootBatch::prepare(
        &workspace,
        &closure,
        &config.panics,
        &config.documentation.overrides,
        requests,
    )
    .map_err(|source| TypedPanicEvaluationError::Input(Box::new(source)))?;
    let prepared_roots = batch.into_roots();
    if prepared_roots.len() != roots.len() {
        return Err(TypedPanicEvaluationError::PreparedRootCount {
            expected: roots.len(),
            actual: prepared_roots.len(),
        });
    }
    let presentation_anchors = FunctionPresentationIndex::build(&workspace)?;
    let relation_index = WorkspaceRelationIndex::open(&workspace)
        .map_err(|source| TypedPanicEvaluationError::Relations(Box::new(source)))?;
    let prepared = PreparedTypedPanicWorkspace {
        registry: &registry,
        workspace: &workspace,
        render_contexts: &opened.render_contexts,
        presentation_anchors: &presentation_anchors,
    };

    let roots = prepared_roots
        .into_iter()
        .zip(roots)
        .map(|(root_input, request)| {
            let root = root_input.root().clone();
            let mut relation_builder = CompositionRelationBuilder::new(
                &root,
                prepared.workspace,
                prepared.registry.composition_relations(),
            )
            .map_err(|source| TypedPanicEvaluationError::Composition(Box::new(source)))?;
            let emitted = root_input
                .emit(&mut relation_builder)
                .map_err(|source| TypedPanicEvaluationError::Input(Box::new(source)))?;
            let relations = relation_builder
                .finalize()
                .map_err(|source| TypedPanicEvaluationError::Composition(Box::new(source)))?;
            let graph = relation_index
                .bind(&root, relations)
                .map_err(|source| TypedPanicEvaluationError::Relations(Box::new(source)))?;
            let inputs = emitted
                .resolve(
                    prepared.workspace,
                    &graph,
                    prepared.registry.composition_relations(),
                )
                .map_err(|source| TypedPanicEvaluationError::Input(Box::new(source)))?;
            let evaluation = WorkspaceEvaluationView::from_graph(prepared.workspace, graph)
                .map_err(|source| TypedPanicEvaluationError::Relations(Box::new(source)))?;
            let mut evaluated = EvaluationDb::new();
            prepared
                .registry
                .run_workspace_evaluation(&inputs, &root, &evaluation, &mut evaluated)
                .map_err(|source| TypedPanicEvaluationError::Evaluation(Box::new(source)))?;
            let results = evaluated
                .finish()
                .map_err(|source| TypedPanicEvaluationError::Results(Box::new(source)))?;
            let issues = results
                .issues::<UnsatisfiedCompilerAssertIssue>(prepared.registry.schemas())
                .map_err(|source| TypedPanicEvaluationError::Results(Box::new(source)))?;
            project_root_report(&prepared, &inputs, request, root, issues)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(TypedPanicBatchReport {
        roots,
        source_files,
    })
}

pub(super) fn permanent_source_files(
    workspace: &WorkspaceFactView<'_>,
) -> Result<Vec<SourceFileIr>, TypedPanicEvaluationError> {
    let mut files = BTreeMap::<SourceFileId, SourceFileIr>::new();
    for scope in workspace.scopes() {
        let view = workspace
            .artifact(scope)
            .map_err(|source| TypedPanicEvaluationError::Workspace(Box::new(source)))?;
        for file in view
            .table::<SourceFileEntity>()
            .map_err(|source| TypedPanicEvaluationError::ArtifactView {
                scope: scope.clone(),
                source: Box::new(source),
            })?
            .iter()
        {
            let file = SourceFileIr {
                id: SourceFileId::new(file.id()),
                filename: file.filename().to_owned(),
                content_hash: file.content_hash().to_owned(),
                byte_len: file.byte_len(),
            };
            match files.entry(file.id.clone()) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(file);
                }
                std::collections::btree_map::Entry::Occupied(entry) => {
                    if entry.get() != &file {
                        return Err(TypedPanicEvaluationError::ConflictingSourceFileIdentity {
                            file: file.id,
                        });
                    }
                }
            }
        }
    }
    Ok(files.into_values().collect())
}

pub(super) fn compiler_assert_root_request(
    root: &InterpretationRoot,
    config: &SniffTestConfig,
) -> CompilerAssertRootRequest {
    CompilerAssertRootRequest::new(
        FunctionKey::new(root.function.def_path_hash, root.function.instance_hash),
        match config.analysis.callable_edge_attribution {
            CallableEdgeAttribution::ErasureSites => CallAttributionRole::ErasureSite,
            CallableEdgeAttribution::CallSites => CallAttributionRole::CallSite,
        },
        match config.analysis.marker_probing {
            MarkerProbing::SourceCallsite => MarkerProbe::SourceCallsite,
            MarkerProbing::MacroDefinitionFirst => MarkerProbe::MacroDefinitionFirst,
        },
        config.analysis.node_limit,
    )
}

fn project_root_report(
    prepared: &PreparedTypedPanicWorkspace<'_, '_>,
    inputs: &CompilerAssertRootInputs,
    request: &InterpretationRoot,
    root: EvaluationRoot,
    issues: Vec<TypedEvaluatedIssue<UnsatisfiedCompilerAssertIssue>>,
) -> RootTypedPanicEvaluation {
    let projector = CompilerAssertTraceProjector::prepare(inputs)
        .map_err(|source| TypedPanicEvaluationError::Trace(Box::new(source)))?;
    let issues = issues
        .into_iter()
        .map(|issue| project_issue(prepared, &projector, &root, issue))
        .collect::<Result<Vec<_>, _>>()?;
    let presentation_range = prepared.presentation_anchors.range(&root.entity)?;
    Ok(TypedPanicRootReport {
        root,
        function: request.function,
        path: request.path.clone(),
        kind: request.kind,
        presentation_range,
        issues,
    })
}

fn project_issue(
    prepared: &PreparedTypedPanicWorkspace<'_, '_>,
    projector: &CompilerAssertTraceProjector<'_>,
    root: &EvaluationRoot,
    issue: TypedEvaluatedIssue<UnsatisfiedCompilerAssertIssue>,
) -> Result<TypedPanicIssueReport, TypedPanicEvaluationError> {
    let trace = projector
        .project(issue.data.witness_order())
        .map_err(|source| TypedPanicEvaluationError::Trace(Box::new(source)))?;
    validate_issue_trace(projector, root, &issue, &trace)?;
    let assertion_scope = issue.data.assertion().scope();
    let render_cx = prepared
        .render_contexts
        .get(assertion_scope)
        .ok_or_else(|| TypedPanicEvaluationError::MissingRenderContext {
            scope: assertion_scope.clone(),
        })?;
    let diagnostic = prepared
        .registry
        .rendering()
        .render(&issue.data, render_cx)
        .map_err(|source| TypedPanicEvaluationError::Render(Box::new(source)))?;
    let presentation = compiler_assert_presentation(issue.data.kind());
    let presentation_range = trace
        .steps()
        .last()
        .and_then(|step| step.source_key())
        .map(source_range);
    Ok(TypedPanicIssueReport {
        compiler_assert_kind: presentation.public_kind(),
        reason: presentation.reason().to_owned(),
        target: presentation.target().to_owned(),
        diagnostic,
        presentation_range,
        trace,
        issue,
    })
}

fn validate_issue_trace(
    projector: &CompilerAssertTraceProjector<'_>,
    root: &EvaluationRoot,
    issue: &TypedEvaluatedIssue<UnsatisfiedCompilerAssertIssue>,
    trace: &CompilerAssertSemanticTrace,
) -> Result<(), TypedPanicEvaluationError> {
    let expected = projector
        .assertion(issue.data.witness_order())
        .map_err(|_| invalid_trace_projection(issue, "witness order has no prepared assertion"))?;
    if &issue.context.root != root
        || issue.context.source.as_ref() != Some(issue.data.assertion())
        || issue.context.endpoint.as_ref() != Some(issue.data.endpoint())
        || issue.context.trace.as_ref() != Some(expected.trace())
        || trace.assertion() != issue.data.assertion()
        || &trace.endpoint().erase() != issue.data.endpoint()
        || trace.witness_order() != issue.data.witness_order()
    {
        return Err(invalid_trace_projection(
            issue,
            "evaluated issue context disagrees with the prepared permanent witness",
        ));
    }
    if trace
        .steps()
        .last()
        .map(CompilerAssertSemanticTraceStep::edge)
        != Some(CompilerAssertSemanticEdge::Assert(issue.data.kind()))
    {
        return Err(invalid_trace_projection(
            issue,
            "semantic trace does not terminate at the evaluated compiler assertion",
        ));
    }
    Ok(())
}

fn invalid_trace_projection(
    issue: &TypedEvaluatedIssue<UnsatisfiedCompilerAssertIssue>,
    reason: impl Into<String>,
) -> TypedPanicEvaluationError {
    TypedPanicEvaluationError::InvalidSemanticTraceProjection {
        issue: issue.reference.clone(),
        reason: reason.into(),
    }
}

fn typed_panic_registry()
-> Result<AnalysisRegistry<CompilerAssertRootInputs>, PackRegistrationError> {
    let mut registry = AnalysisRegistry::new();
    registry.install(&CollectedArtifactSchemaPack)?;
    registry.install(&HumanEvidencePack)?;
    registry.install(&PanicPack)?;
    registry.install(&CompilerAssertInputPack)?;
    Ok(registry)
}

fn canonical_persisted_scope(
    artifact: &RustcArtifactId,
) -> Result<ArtifactScopeId, TypedPanicEvaluationError> {
    ArtifactScopeId::for_persisted(artifact.stable_crate_id, artifact.svh.clone()).map_err(
        |source| TypedPanicEvaluationError::ArtifactScope {
            artifact: artifact.to_string(),
            source: Box::new(source),
        },
    )
}

pub(super) fn source_range(anchor: &SourceAnchorKey) -> SourceRangeIr {
    SourceRangeIr {
        file: SourceFileId::new(anchor.file()),
        byte_start: anchor.byte_start(),
        byte_end: anchor.byte_end(),
    }
}

pub(super) const fn semantic_edge_label(edge: CompilerAssertSemanticEdge) -> &'static str {
    match edge {
        CompilerAssertSemanticEdge::MacroExpansion => "macro-expansion",
        CompilerAssertSemanticEdge::Call(kind) => call_kind_label(kind),
        CompilerAssertSemanticEdge::Assert(_) => "assert",
    }
}

pub(super) const fn semantic_edge_order(edge: CompilerAssertSemanticEdge) -> u8 {
    match edge {
        CompilerAssertSemanticEdge::MacroExpansion => 8,
        CompilerAssertSemanticEdge::Call(kind) => call_kind_order(kind),
        CompilerAssertSemanticEdge::Assert(_) => 11,
    }
}

const fn call_kind_label(kind: CallKind) -> &'static str {
    match kind {
        CallKind::DirectCall => "direct-call",
        CallKind::TailCall => "tail-call",
        CallKind::FnPointerReify => "fn-pointer-reify",
        CallKind::ClosureFnPointerReify => "closure-fn-pointer-reify",
        CallKind::FnPointerCallTarget => "fn-pointer-call-target",
        CallKind::DynObjectCast => "dyn-object-cast",
        CallKind::VTableEntry => "vtable-entry",
        CallKind::DynDispatchVTableEntry => "dyn-dispatch-vtable-entry",
        CallKind::MacroExpansion => "macro-expansion",
        CallKind::ConstBody => "const-body",
        CallKind::CoroutineBody => "coroutine-body",
        CallKind::Assert => "assert",
        CallKind::IndirectCall => "indirect-call",
    }
}

const fn call_kind_order(kind: CallKind) -> u8 {
    match kind {
        CallKind::DirectCall => 0,
        CallKind::TailCall => 1,
        CallKind::FnPointerReify => 2,
        CallKind::ClosureFnPointerReify => 3,
        CallKind::FnPointerCallTarget => 4,
        CallKind::DynObjectCast => 5,
        CallKind::VTableEntry => 6,
        CallKind::DynDispatchVTableEntry => 7,
        CallKind::MacroExpansion => 8,
        CallKind::ConstBody => 9,
        CallKind::CoroutineBody => 10,
        CallKind::Assert => 11,
        CallKind::IndirectCall => 12,
    }
}

#[cfg(test)]
mod tests;
