//! Compile-time composition of schemas, passes, and presentation adapters.
//!
//! An analysis pack is ordinary Rust code installed by the binary's
//! composition root. Adding a pack extends registries keyed by stable schema
//! IDs; it does not add variants to a core event, effect, requirement, trace,
//! or issue enum.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use super::builder::ArtifactDbBuilder;
use super::composition::presentation::{
    CompositionRelationPresenter, CompositionRenderError, CompositionRenderRegistry,
};
use super::composition::{
    CompositionRegistryError, CompositionRelationRegistry, WorkspaceEvaluationView,
};
use super::encoded::TableKind;
use super::evaluation::{
    EvaluationDb, EvaluationPipelineError, EvaluationRoot, EvaluationRule, EvaluationRuleScheduler,
    RuleRegistrationError,
};
use super::pass::{
    ArtifactPass, ArtifactPassScheduler, CapturedArtifactPass, PassPipelineError,
    PassRegistrationError,
};
use super::registry::{SchemaRegistry, SchemaRegistryError};
use super::render::{IssueRenderer, RelationPresenter, RenderError, RenderRegistry};
use super::schema::{
    CompositionRelationSchema, DerivedSchema, EntitySchema, FactSchema, IssueSchema, PassId,
    RelationSchema, RequirementSchema, RowSchema, SchemaId,
};

/// One compile-time analysis extension.
pub(crate) trait AnalysisPack<C: ?Sized> {
    fn register(&self, registry: &mut AnalysisRegistry<C>) -> Result<(), PackRegistrationError>;
}

/// All infrastructure registrations assembled by the composition root.
pub(crate) struct AnalysisRegistry<C: ?Sized> {
    schemas: SchemaRegistry,
    composition_relations: CompositionRelationRegistry,
    artifact_passes: ArtifactPassScheduler<C>,
    evaluation_rules: EvaluationRuleScheduler<C>,
    rendering: RenderRegistry,
    composition_rendering: CompositionRenderRegistry,
}

impl<C: ?Sized> Default for AnalysisRegistry<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: ?Sized> AnalysisRegistry<C> {
    pub(crate) fn new() -> Self {
        Self {
            schemas: SchemaRegistry::new(),
            composition_relations: CompositionRelationRegistry::new(),
            artifact_passes: ArtifactPassScheduler::default(),
            evaluation_rules: EvaluationRuleScheduler::default(),
            rendering: RenderRegistry::default(),
            composition_rendering: CompositionRenderRegistry::new(),
        }
    }

    /// Installs one pack. Registration failures are fatal composition errors;
    /// callers should discard the registry rather than continue with a
    /// partially installed pack.
    pub(crate) fn install(
        &mut self,
        pack: &impl AnalysisPack<C>,
    ) -> Result<(), PackRegistrationError> {
        pack.register(self)
    }

    pub(crate) fn schemas(&self) -> &SchemaRegistry {
        &self.schemas
    }

    pub(crate) fn artifact_passes(&self) -> &ArtifactPassScheduler<C> {
        &self.artifact_passes
    }

    pub(crate) fn run_artifact_passes(
        &mut self,
        cx: &C,
        committed: &mut ArtifactDbBuilder,
    ) -> Result<(), PassPipelineError> {
        self.artifact_passes.run_all(cx, committed, &self.schemas)
    }

    pub(crate) fn rendering(&self) -> &RenderRegistry {
        &self.rendering
    }

    pub(crate) fn composition_relations(&self) -> &CompositionRelationRegistry {
        &self.composition_relations
    }

    pub(crate) fn composition_rendering(&self) -> &CompositionRenderRegistry {
        &self.composition_rendering
    }

    pub(crate) fn evaluation_rules(&self) -> &EvaluationRuleScheduler<C> {
        &self.evaluation_rules
    }

    pub(crate) fn run_evaluation<'a>(
        &self,
        services: &C,
        root: &'a EvaluationRoot,
        artifact: super::view::ArtifactDbView<'a>,
        committed: &mut EvaluationDb,
    ) -> Result<(), EvaluationPipelineError> {
        self.evaluation_rules
            .run_all(services, root, artifact, committed)
    }

    pub(crate) fn run_workspace_evaluation<'a>(
        &self,
        services: &C,
        root: &EvaluationRoot,
        evaluation: &'a WorkspaceEvaluationView<'a>,
        committed: &mut EvaluationDb,
    ) -> Result<(), EvaluationPipelineError> {
        self.evaluation_rules
            .run_all_workspace(services, root, evaluation, committed)
    }

    pub(crate) fn register_entity<E: EntitySchema>(&mut self) -> Result<(), PackRegistrationError> {
        self.schemas.register_entity::<E>()?;
        Ok(())
    }

    pub(crate) fn register_fact<F: FactSchema>(&mut self) -> Result<(), PackRegistrationError> {
        self.schemas.register_fact::<F>()?;
        Ok(())
    }

    pub(crate) fn register_relation<R: RelationSchema>(
        &mut self,
    ) -> Result<(), PackRegistrationError> {
        self.schemas.register_relation::<R>()?;
        Ok(())
    }

    pub(crate) fn register_composition_relation<R: CompositionRelationSchema>(
        &mut self,
    ) -> Result<(), PackRegistrationError> {
        self.composition_relations.register::<R>(&self.schemas)?;
        Ok(())
    }

    pub(crate) fn register_requirement<R: RequirementSchema>(
        &mut self,
    ) -> Result<(), PackRegistrationError> {
        self.schemas.register_requirement::<R>()?;
        Ok(())
    }

    pub(crate) fn register_derived<D: DerivedSchema>(
        &mut self,
    ) -> Result<(), PackRegistrationError> {
        self.schemas.register_derived::<D>()?;
        Ok(())
    }

    pub(crate) fn register_issue<I: IssueSchema>(&mut self) -> Result<(), PackRegistrationError> {
        self.schemas.register_issue::<I>()?;
        Ok(())
    }

    pub(crate) fn register_artifact_pass(
        &mut self,
        pass: impl ArtifactPass<C> + 'static,
    ) -> Result<(), PackRegistrationError> {
        let captured = CapturedArtifactPass::capture(pass);
        let descriptor = captured.descriptor();
        for schema in &descriptor.reads {
            self.ensure_artifact_pass_schema(&descriptor.id, schema, PackSchemaAccess::Read)?;
        }
        for schema in &descriptor.writes {
            self.ensure_artifact_pass_schema(&descriptor.id, schema, PackSchemaAccess::Write)?;
        }
        self.artifact_passes.register_captured(captured)?;
        Ok(())
    }

    pub(crate) fn register_evaluation_rule(
        &mut self,
        rule: impl EvaluationRule<C> + 'static,
    ) -> Result<(), PackRegistrationError> {
        self.evaluation_rules.register(&self.schemas, rule)?;
        Ok(())
    }

    pub(crate) fn register_issue_renderer<I, R>(
        &mut self,
        renderer: R,
    ) -> Result<(), PackRegistrationError>
    where
        I: IssueSchema,
        R: IssueRenderer<I> + 'static,
    {
        self.ensure_schema_kind::<I>(TableKind::Issue)?;
        self.rendering.register_issue::<I, R>(renderer)?;
        Ok(())
    }

    pub(crate) fn register_relation_presenter<R, P>(
        &mut self,
        presenter: P,
    ) -> Result<(), PackRegistrationError>
    where
        R: RelationSchema,
        P: RelationPresenter<R> + 'static,
    {
        self.ensure_schema_kind::<R>(TableKind::Relation)?;
        self.rendering.register_relation::<R, P>(presenter)?;
        Ok(())
    }

    pub(crate) fn register_composition_relation_presenter<R, P>(
        &mut self,
        presenter: P,
    ) -> Result<(), PackRegistrationError>
    where
        R: CompositionRelationSchema,
        P: CompositionRelationPresenter<R> + 'static,
    {
        self.composition_rendering
            .register::<R, P>(&self.composition_relations, presenter)?;
        Ok(())
    }

    fn ensure_schema_kind<S: RowSchema>(
        &self,
        expected: TableKind,
    ) -> Result<(), PackRegistrationError> {
        let descriptor = self.schemas.descriptor_for::<S>()?;
        let registered = descriptor.kind();
        if registered != expected {
            return Err(SchemaRegistryError::KindMismatch {
                schema: descriptor.id().clone(),
                registered,
                incoming: expected,
            }
            .into());
        }
        Ok(())
    }

    fn ensure_pass_schema(
        &self,
        pass: &PassId,
        schema: &SchemaId,
        access: PackSchemaAccess,
    ) -> Result<(), PackRegistrationError> {
        if self.schemas.descriptor(schema).is_some() {
            Ok(())
        } else {
            Err(PackRegistrationError::UnregisteredPassSchema {
                pass: pass.clone(),
                schema: schema.clone(),
                access,
            })
        }
    }

    fn ensure_artifact_pass_schema(
        &self,
        pass: &PassId,
        schema: &SchemaId,
        access: PackSchemaAccess,
    ) -> Result<(), PackRegistrationError> {
        self.ensure_pass_schema(pass, schema, access)?;
        let kind = self
            .schemas
            .descriptor(schema)
            .expect("pass schemas were validated before checking their kind")
            .kind();
        if matches!(kind, TableKind::Derived | TableKind::Issue) {
            return Err(PackRegistrationError::ArtifactPassAccessesEvaluationTable {
                pass: pass.clone(),
                schema: schema.clone(),
                access,
                kind,
            });
        }
        Ok(())
    }
}

/// Whether a pass expected to consume or produce an unregistered schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PackSchemaAccess {
    Read,
    Write,
}

impl Display for PackSchemaAccess {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Read => "read",
            Self::Write => "write",
        })
    }
}

/// Structured failure while composing an analysis pack.
#[derive(Debug)]
pub(crate) enum PackRegistrationError {
    Schema(SchemaRegistryError),
    CompositionSchema(CompositionRegistryError),
    Pass(PassRegistrationError),
    Evaluation(RuleRegistrationError),
    Render(RenderError),
    CompositionRender(CompositionRenderError),
    UnregisteredPassSchema {
        pass: PassId,
        schema: SchemaId,
        access: PackSchemaAccess,
    },
    ArtifactPassAccessesEvaluationTable {
        pass: PassId,
        schema: SchemaId,
        access: PackSchemaAccess,
        kind: TableKind,
    },
    InvalidPack {
        message: String,
    },
}

impl PackRegistrationError {
    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::InvalidPack {
            message: message.into(),
        }
    }
}

impl Display for PackRegistrationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Schema(source) => write!(formatter, "schema registration failed: {source}"),
            Self::CompositionSchema(source) => {
                write!(
                    formatter,
                    "composition schema registration failed: {source}"
                )
            }
            Self::Pass(source) => write!(formatter, "artifact pass registration failed: {source}"),
            Self::Evaluation(source) => {
                write!(formatter, "evaluation rule registration failed: {source}")
            }
            Self::Render(source) => write!(formatter, "renderer registration failed: {source}"),
            Self::CompositionRender(source) => {
                write!(
                    formatter,
                    "composition presenter registration failed: {source}"
                )
            }
            Self::UnregisteredPassSchema {
                pass,
                schema,
                access,
            } => write!(
                formatter,
                "artifact pass {pass:?} declares {access} access to unregistered schema {schema:?}"
            ),
            Self::ArtifactPassAccessesEvaluationTable {
                pass,
                schema,
                access,
                kind,
            } => write!(
                formatter,
                "artifact pass {pass:?} cannot {access} evaluation-only {kind:?} schema {schema:?}"
            ),
            Self::InvalidPack { message } => formatter.write_str(message),
        }
    }
}

impl Error for PackRegistrationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Schema(source) => Some(source),
            Self::CompositionSchema(source) => Some(source),
            Self::Pass(source) => Some(source),
            Self::Evaluation(source) => Some(source),
            Self::Render(source) => Some(source),
            Self::CompositionRender(source) => Some(source),
            Self::UnregisteredPassSchema { .. }
            | Self::ArtifactPassAccessesEvaluationTable { .. }
            | Self::InvalidPack { .. } => None,
        }
    }
}

impl From<SchemaRegistryError> for PackRegistrationError {
    fn from(source: SchemaRegistryError) -> Self {
        Self::Schema(source)
    }
}

impl From<CompositionRegistryError> for PackRegistrationError {
    fn from(source: CompositionRegistryError) -> Self {
        Self::CompositionSchema(source)
    }
}

impl From<PassRegistrationError> for PackRegistrationError {
    fn from(source: PassRegistrationError) -> Self {
        Self::Pass(source)
    }
}

impl From<RuleRegistrationError> for PackRegistrationError {
    fn from(source: RuleRegistrationError) -> Self {
        Self::Evaluation(source)
    }
}

impl From<RenderError> for PackRegistrationError {
    fn from(source: RenderError) -> Self {
        Self::Render(source)
    }
}

impl From<CompositionRenderError> for PackRegistrationError {
    fn from(source: CompositionRenderError) -> Self {
        Self::CompositionRender(source)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::rc::Rc;

    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::analysis::facts::builder::ArtifactDbBuilder;
    use crate::analysis::facts::composition::WorkspaceRelationRef;
    use crate::analysis::facts::composition::presentation::{
        CompositionRelationPresenter, CompositionRenderCx,
    };
    use crate::analysis::facts::encoded::{ArtifactFactIr, EntityRef};
    use crate::analysis::facts::evaluation::{
        DomainId, EvaluationCx, EvaluationDb, EvaluationInput, EvaluationIssueContext,
        EvaluationOutput, EvaluationRoot, EvaluationRule, ObligationRecord, RelationTrace,
        RuleDescriptor, RuleError,
    };
    use crate::analysis::facts::pass::{PassDescriptor, PassError, PassInput, PassOutput};
    use crate::analysis::facts::relations::RelationGraph;
    use crate::analysis::facts::render::{RelationPresentation, RenderCx, RenderedDiagnostic};
    use crate::analysis::facts::schema::{CompositionRelationSchema, PassId, RowSchema, SchemaId};
    use crate::analysis::facts::view::ArtifactDbView;
    use crate::analysis::facts::workspace::{
        ArtifactScopeId, ScopedEntityRef, ScopedRelationRef, ScopedRowRef,
    };

    #[derive(Clone, Serialize, Deserialize)]
    struct SampleNode {
        stable_name: String,
    }

    impl RowSchema for SampleNode {
        const ID: &'static str = "sample.pack.node";
        const VERSION: u32 = 1;
    }

    impl EntitySchema for SampleNode {
        type Key = String;

        fn key(&self) -> Self::Key {
            self.stable_name.clone()
        }
    }

    #[derive(Clone, Serialize, Deserialize)]
    struct SampleFact {
        detail: String,
    }

    impl RowSchema for SampleFact {
        const ID: &'static str = "sample.pack.fact";
        const VERSION: u32 = 1;
    }

    impl FactSchema for SampleFact {}

    #[derive(Clone, Serialize, Deserialize)]
    struct SampleEdge;

    impl RowSchema for SampleEdge {
        const ID: &'static str = "sample.pack.edge";
        const VERSION: u32 = 1;
    }

    impl RelationSchema for SampleEdge {
        type From = SampleNode;
        type To = SampleNode;
    }

    #[derive(Clone, Serialize, Deserialize)]
    struct SampleCompositionEdge;

    impl RowSchema for SampleCompositionEdge {
        const ID: &'static str = "sample.pack.composition-edge";
        const VERSION: u32 = 1;
    }

    impl RelationSchema for SampleCompositionEdge {
        type From = SampleNode;
        type To = SampleNode;
    }

    impl CompositionRelationSchema for SampleCompositionEdge {}

    #[derive(Clone, Serialize, Deserialize)]
    struct SampleRequirement {
        statement: String,
    }

    impl RowSchema for SampleRequirement {
        const ID: &'static str = "sample.pack.requirement";
        const VERSION: u32 = 1;
    }

    impl RequirementSchema for SampleRequirement {}

    #[derive(Clone, Serialize, Deserialize)]
    struct SampleIssue {
        message: String,
    }

    impl RowSchema for SampleIssue {
        const ID: &'static str = "sample.pack.issue";
        const VERSION: u32 = 1;
    }

    impl IssueSchema for SampleIssue {}

    #[derive(Clone, Serialize, Deserialize)]
    struct SampleDerived;

    impl RowSchema for SampleDerived {
        const ID: &'static str = "sample.pack.derived";
        const VERSION: u32 = 1;
    }

    impl DerivedSchema for SampleDerived {}

    #[derive(Clone, Serialize, Deserialize)]
    struct FactMarkedIssue;

    impl RowSchema for FactMarkedIssue {
        const ID: &'static str = "sample.pack.fact-marked-issue";
        const VERSION: u32 = 1;
    }

    impl FactSchema for FactMarkedIssue {}
    impl IssueSchema for FactMarkedIssue {}

    struct FactMarkedIssueRenderer;

    impl IssueRenderer<FactMarkedIssue> for FactMarkedIssueRenderer {
        fn render(&self, _issue: &FactMarkedIssue, _cx: &RenderCx<'_>) -> RenderedDiagnostic {
            RenderedDiagnostic::new("must not be registered")
        }
    }

    #[derive(Clone, Serialize, Deserialize)]
    struct FactMarkedRelation;

    impl RowSchema for FactMarkedRelation {
        const ID: &'static str = "sample.pack.fact-marked-relation";
        const VERSION: u32 = 1;
    }

    impl FactSchema for FactMarkedRelation {}

    impl RelationSchema for FactMarkedRelation {
        type From = SampleNode;
        type To = SampleNode;
    }

    struct FactMarkedRelationPresenter;

    impl RelationPresenter<FactMarkedRelation> for FactMarkedRelationPresenter {
        fn present(
            &self,
            _relation: &FactMarkedRelation,
            _cx: &RenderCx<'_>,
        ) -> RelationPresentation {
            RelationPresentation::new("must not be registered")
        }
    }

    struct SamplePass;

    impl ArtifactPass<()> for SamplePass {
        fn descriptor(&self) -> PassDescriptor {
            PassDescriptor::new(PassId::new("sample.pack.collect").unwrap()).with_writes([
                SchemaId::new(SampleNode::ID).unwrap(),
                SchemaId::new(SampleFact::ID).unwrap(),
                SchemaId::new(SampleEdge::ID).unwrap(),
                SchemaId::new(SampleRequirement::ID).unwrap(),
            ])
        }

        fn run(
            &mut self,
            _cx: &(),
            _input: PassInput<'_>,
            output: &mut PassOutput<'_>,
        ) -> Result<(), PassError> {
            let start = output.insert_entity(&SampleNode {
                stable_name: String::from("start"),
            })?;
            let target = output.insert_entity(&SampleNode {
                stable_name: String::from("target"),
            })?;
            let requirement = output.insert_requirement(&SampleRequirement {
                statement: String::from("sample condition"),
            })?;
            let meta = output.fact_meta();
            let meta = output.with_fact_owner(meta, &target)?;
            let meta = output.with_fact_requirement(meta, &requirement)?;
            output.insert_fact(
                &SampleFact {
                    detail: String::from("observed target"),
                },
                meta,
            )?;
            output.relate(&start, &target, &SampleEdge)?;
            Ok(())
        }
    }

    struct StatefulDescriptorPass {
        calls: Rc<Cell<u32>>,
    }

    struct DerivedWritingPass;

    impl ArtifactPass<()> for DerivedWritingPass {
        fn descriptor(&self) -> PassDescriptor {
            PassDescriptor::new(PassId::new("sample.pack.write-derived").unwrap())
                .with_writes([SchemaId::new(SampleDerived::ID).unwrap()])
        }

        fn run(
            &mut self,
            _cx: &(),
            _input: PassInput<'_>,
            _output: &mut PassOutput<'_>,
        ) -> Result<(), PassError> {
            Ok(())
        }
    }

    struct DerivedReadingPass;

    impl ArtifactPass<()> for DerivedReadingPass {
        fn descriptor(&self) -> PassDescriptor {
            PassDescriptor::new(PassId::new("sample.pack.read-derived").unwrap())
                .with_reads([SchemaId::new(SampleDerived::ID).unwrap()])
        }

        fn run(
            &mut self,
            _cx: &(),
            _input: PassInput<'_>,
            _output: &mut PassOutput<'_>,
        ) -> Result<(), PassError> {
            Ok(())
        }
    }

    impl ArtifactPass<()> for StatefulDescriptorPass {
        fn descriptor(&self) -> PassDescriptor {
            let call = self.calls.get();
            self.calls.set(call + 1);
            let output = if call == 0 {
                SampleFact::ID
            } else {
                "sample.pack.unvalidated-output"
            };
            PassDescriptor::new(PassId::new("sample.pack.stateful-descriptor").unwrap())
                .with_writes([SchemaId::new(output).unwrap()])
        }

        fn run(
            &mut self,
            _cx: &(),
            _input: PassInput<'_>,
            _output: &mut PassOutput<'_>,
        ) -> Result<(), PassError> {
            Ok(())
        }
    }

    struct SampleRenderer;

    impl IssueRenderer<SampleIssue> for SampleRenderer {
        fn render(&self, issue: &SampleIssue, _cx: &RenderCx<'_>) -> RenderedDiagnostic {
            RenderedDiagnostic::new(&issue.message)
        }
    }

    struct SampleEvaluationRule;

    impl EvaluationRule<()> for SampleEvaluationRule {
        fn descriptor(&self) -> RuleDescriptor {
            RuleDescriptor::new(PassId::new("sample.pack.evaluate").unwrap())
                .read::<SampleFact>()
                .read::<SampleEdge>()
                .write_derived::<ObligationRecord>()
                .write_issue::<SampleIssue>()
        }

        fn evaluate(
            &self,
            cx: &EvaluationCx<'_, ()>,
            input: &EvaluationInput<'_>,
            output: &mut EvaluationOutput<'_>,
        ) -> Result<(), RuleError> {
            for fact in input.artifact_facts::<SampleFact>()? {
                let Some(local_endpoint) = fact.metadata.owner.clone() else {
                    continue;
                };
                let scope = cx.root().entity.scope().clone();
                let endpoint = ScopedEntityRef::new(scope.clone(), local_endpoint.clone());
                let relation = input
                    .artifact_relations::<SampleEdge>()?
                    .into_iter()
                    .find(|relation| {
                        relation.from.erase() == *cx.root().entity.entity()
                            && relation.to.erase() == local_endpoint
                    })
                    .ok_or_else(|| RuleError::failed("sample fact has no provenance edge"))?;
                let trace = RelationTrace::new(
                    cx.root().entity.clone(),
                    endpoint.clone(),
                    vec![WorkspaceRelationRef::Artifact(ScopedRelationRef::new(
                        scope.clone(),
                        relation.relation,
                    ))],
                );
                let context = EvaluationIssueContext::new(cx.root().clone())
                    .with_source(ScopedRowRef::new(
                        scope.clone(),
                        fact.fact.reference.clone(),
                    ))
                    .with_endpoint(endpoint.clone())
                    .with_trace(trace.clone());
                output.emit_obligation(&ObligationRecord::new(
                    cx.root().domain.clone(),
                    ScopedRowRef::new(scope.clone(), fact.fact.reference),
                    endpoint.clone(),
                    fact.metadata
                        .requirements
                        .into_iter()
                        .map(|requirement| ScopedRowRef::new(scope.clone(), requirement))
                        .collect(),
                    endpoint,
                    trace,
                ))?;
                output.emit_issue(
                    &SampleIssue {
                        message: format!("sample issue: {}", fact.fact.data.detail),
                    },
                    context,
                )?;
            }
            Ok(())
        }
    }

    struct SamplePresenter;

    impl RelationPresenter<SampleEdge> for SamplePresenter {
        fn present(&self, _relation: &SampleEdge, _cx: &RenderCx<'_>) -> RelationPresentation {
            RelationPresentation::new("sample edge")
        }
    }

    struct SampleCompositionPresenter;

    impl CompositionRelationPresenter<SampleCompositionEdge> for SampleCompositionPresenter {
        fn present(
            &self,
            _relation: &SampleCompositionEdge,
            _metadata: &crate::analysis::facts::composition::CompositionRelationIndexRow,
            _cx: &CompositionRenderCx<'_>,
        ) -> RelationPresentation {
            RelationPresentation::new("sample composition edge")
        }
    }

    struct SamplePack;

    impl AnalysisPack<()> for SamplePack {
        fn register(
            &self,
            registry: &mut AnalysisRegistry<()>,
        ) -> Result<(), PackRegistrationError> {
            registry.register_entity::<SampleNode>()?;
            registry.register_fact::<SampleFact>()?;
            registry.register_relation::<SampleEdge>()?;
            registry.register_composition_relation::<SampleCompositionEdge>()?;
            registry.register_requirement::<SampleRequirement>()?;
            registry.register_derived::<ObligationRecord>()?;
            registry.register_issue::<SampleIssue>()?;
            registry.register_artifact_pass(SamplePass)?;
            registry.register_evaluation_rule(SampleEvaluationRule)?;
            registry.register_issue_renderer::<SampleIssue, _>(SampleRenderer)?;
            registry.register_relation_presenter::<SampleEdge, _>(SamplePresenter)?;
            registry.register_composition_relation_presenter::<SampleCompositionEdge, _>(
                SampleCompositionPresenter,
            )?;
            Ok(())
        }
    }

    fn sample_evaluation_root(entity: EntityRef) -> EvaluationRoot {
        EvaluationRoot::new(
            DomainId::new("sample.pack.domain").unwrap(),
            ScopedEntityRef::new(
                ArtifactScopeId::new("sample.pack.generation").unwrap(),
                entity,
            ),
        )
    }

    fn assert_sample_composition_registrations(registry: &AnalysisRegistry<()>) {
        let schema = SchemaId::new(SampleCompositionEdge::ID).unwrap();
        assert!(
            registry
                .composition_relations()
                .descriptor(&schema)
                .is_some()
        );
        assert!(registry.composition_rendering().has_presenter(&schema));
    }

    #[test]
    fn unrelated_pack_extends_every_registry_without_a_core_enum() {
        let mut registry = AnalysisRegistry::<()>::new();

        registry.install(&SamplePack).expect("install sample pack");

        for schema in [
            SampleNode::ID,
            SampleFact::ID,
            SampleEdge::ID,
            SampleRequirement::ID,
            ObligationRecord::ID,
            SampleIssue::ID,
        ] {
            assert!(
                registry
                    .schemas()
                    .descriptor(&SchemaId::new(schema).unwrap())
                    .is_some()
            );
        }
        assert!(
            registry
                .artifact_passes()
                .descriptor(&PassId::new("sample.pack.collect").unwrap())
                .is_some()
        );
        assert!(
            registry
                .evaluation_rules()
                .descriptor(&PassId::new("sample.pack.evaluate").unwrap())
                .is_some()
        );
        assert!(
            registry
                .rendering()
                .has_issue_renderer(&SchemaId::new(SampleIssue::ID).unwrap())
        );
        assert!(
            registry
                .rendering()
                .has_relation_presenter(&SchemaId::new(SampleEdge::ID).unwrap())
        );
        assert_sample_composition_registrations(&registry);

        let pass = PassId::new("sample.pack.collect").unwrap();
        assert!(registry.artifact_passes().descriptor(&pass).is_some());
        let mut committed = ArtifactDbBuilder::new();
        registry
            .run_artifact_passes(&(), &mut committed)
            .expect("execute sample collection pass");
        let artifact = committed
            .finalize(registry.schemas())
            .expect("finalize sample artifact");
        let encoded = serde_json::to_vec(&artifact).expect("serialize registered tables");
        let artifact: ArtifactFactIr =
            serde_json::from_slice(&encoded).expect("deserialize registered tables");
        let view = ArtifactDbView::open(&artifact, registry.schemas())
            .expect("open validated sample artifact");
        assert_eq!(view.table::<SampleNode>().unwrap().len(), 2);
        assert_eq!(view.table::<SampleFact>().unwrap().len(), 1);
        assert_eq!(view.table::<SampleRequirement>().unwrap().len(), 1);

        let start = view
            .entity_id_by_key::<SampleNode>(&String::from("start"))
            .unwrap()
            .expect("start entity");
        let target = view
            .entity_id_by_key::<SampleNode>(&String::from("target"))
            .unwrap()
            .expect("target entity");
        let path = RelationGraph::new(view)
            .shortest_path(&start.erase(), &target.erase())
            .expect("sample relation path");
        assert_eq!(path.len(), 1);

        let root = sample_evaluation_root(start.erase());
        let mut evaluated = EvaluationDb::new();
        registry
            .run_evaluation(&(), &root, view, &mut evaluated)
            .expect("evaluate sample root");
        let results = evaluated.finish().expect("finalize evaluated issues");
        let issues = results
            .issues::<SampleIssue>(registry.schemas())
            .expect("decode evaluated sample issues");
        let obligations = results
            .derived_rows::<ObligationRecord>(registry.schemas())
            .expect("decode evaluated sample obligations");
        assert_eq!(issues.len(), 1);
        assert_eq!(obligations.len(), 1);
        assert_eq!(obligations[0].data.requirements().len(), 1);

        let render_cx = RenderCx::open(&artifact, registry.schemas())
            .expect("validated artifact remains valid for rendering");
        let diagnostic = registry
            .rendering()
            .render(&issues[0].data, &render_cx)
            .expect("render sample issue");
        assert_eq!(diagnostic.message, "sample issue: observed target");
        let presented = registry
            .rendering()
            .present_path(&path, &render_cx)
            .expect("present persisted sample path");
        assert_eq!(presented[0].presentation.summary, "sample edge");
    }

    #[test]
    fn installing_the_same_pack_twice_is_a_structured_error() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&SamplePack).expect("install first pack");

        let error = registry
            .install(&SamplePack)
            .expect_err("duplicate schema registration must fail");

        assert!(matches!(error, PackRegistrationError::Schema(_)));
    }

    #[test]
    fn pass_cannot_declare_a_schema_its_pack_did_not_register() {
        let mut registry = AnalysisRegistry::<()>::new();

        let error = registry
            .register_artifact_pass(SamplePass)
            .expect_err("unregistered pass output must fail");

        assert!(matches!(
            error,
            PackRegistrationError::UnregisteredPassSchema {
                pass,
                schema,
                access: PackSchemaAccess::Write,
            } if pass == PassId::new("sample.pack.collect").unwrap()
                && schema == SchemaId::new(SampleNode::ID).unwrap()
        ));
    }

    #[test]
    fn artifact_pass_descriptor_is_captured_once_for_validation_and_storage() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.register_fact::<SampleFact>().unwrap();
        let calls = Rc::new(Cell::new(0));

        registry
            .register_artifact_pass(StatefulDescriptorPass {
                calls: Rc::clone(&calls),
            })
            .expect("the validated descriptor is the descriptor that gets stored");

        assert_eq!(calls.get(), 1);
        let descriptor = registry
            .artifact_passes()
            .descriptor(&PassId::new("sample.pack.stateful-descriptor").unwrap())
            .unwrap();
        assert_eq!(
            descriptor.writes,
            vec![SchemaId::new(SampleFact::ID).unwrap()]
        );
    }

    #[test]
    fn artifact_pass_cannot_write_root_specific_derived_rows() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.register_derived::<SampleDerived>().unwrap();

        let error = registry
            .register_artifact_pass(DerivedWritingPass)
            .expect_err("derived evaluation state must never enter artifact caches");

        assert!(matches!(
            error,
            PackRegistrationError::ArtifactPassAccessesEvaluationTable {
                access: PackSchemaAccess::Write,
                kind: TableKind::Derived,
                ..
            }
        ));
    }

    #[test]
    fn artifact_pass_cannot_read_root_specific_derived_rows() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.register_derived::<SampleDerived>().unwrap();

        let error = registry
            .register_artifact_pass(DerivedReadingPass)
            .expect_err("derived evaluation state must never become an artifact pass input");

        assert!(matches!(
            error,
            PackRegistrationError::ArtifactPassAccessesEvaluationTable {
                access: PackSchemaAccess::Read,
                kind: TableKind::Derived,
                ..
            }
        ));
    }

    #[test]
    fn renderer_requires_its_typed_issue_schema_to_be_registered() {
        let mut registry = AnalysisRegistry::<()>::new();

        let error = registry
            .register_issue_renderer::<SampleIssue, _>(SampleRenderer)
            .expect_err("renderer without issue schema must fail");

        assert!(matches!(error, PackRegistrationError::Schema(_)));
    }

    #[test]
    fn issue_renderer_requires_the_registered_issue_table_kind() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.register_fact::<FactMarkedIssue>().unwrap();

        let error = registry
            .register_issue_renderer::<FactMarkedIssue, _>(FactMarkedIssueRenderer)
            .expect_err("an issue marker must not override the registered fact kind");

        assert!(matches!(
            error,
            PackRegistrationError::Schema(SchemaRegistryError::KindMismatch {
                registered: TableKind::Fact,
                incoming: TableKind::Issue,
                ..
            })
        ));
    }

    #[test]
    fn relation_presenter_requires_the_registered_relation_table_kind() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.register_fact::<FactMarkedRelation>().unwrap();

        let error = registry
            .register_relation_presenter::<FactMarkedRelation, _>(FactMarkedRelationPresenter)
            .expect_err("a relation marker must not override the registered fact kind");

        assert!(matches!(
            error,
            PackRegistrationError::Schema(SchemaRegistryError::KindMismatch {
                registered: TableKind::Fact,
                incoming: TableKind::Relation,
                ..
            })
        ));
    }
}
