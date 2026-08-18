//! Typed issue renderers and relation presenters.
//!
//! Renderers are registered by stable schema ID. Their concrete Rust types are
//! erased only by serializing and deserializing through `serde_json::Value` at
//! the registry boundary; normal renderer implementations receive `&I` or `&R`
//! and never use `Any`, downcasts, or an unsafe typemap.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::marker::PhantomData;

use serde_json::Value;

use super::encoded::{ArtifactFactIr, EntityRef, RelationIndexRow, RowRef, TableKind};
use super::registry::SchemaRegistry;
use super::schema::{IssueSchema, RelationSchema, RowSchema, SchemaId};
use super::view::{ArtifactDbView, PersistedRelation};

/// Read-only infrastructure available while formatting an evaluated issue.
///
/// Policy selection and verified-anchor resolution can be layered onto this
/// context by the CLI adapter. The core context intentionally contains no
/// panic-, safety-, or other domain-specific state.
#[derive(Clone, Copy)]
pub(crate) struct RenderCx<'a> {
    facts: ArtifactDbView<'a>,
}

impl<'a> RenderCx<'a> {
    /// Constructs a rendering context only after the persisted artifact has
    /// crossed the authoritative registry-aware validation boundary.
    pub(crate) fn open(
        artifact: &'a ArtifactFactIr,
        schemas: &'a SchemaRegistry,
    ) -> Result<Self, RenderError> {
        let facts = ArtifactDbView::open(artifact, schemas).map_err(|error| {
            RenderError::InvalidArtifact {
                message: error.to_string(),
            }
        })?;
        Ok(Self { facts })
    }

    /// Reuses an artifact view that already crossed the authoritative
    /// registry-aware validation boundary.
    ///
    /// Workspace projection can retain one validated view per exact artifact
    /// scope and construct cheap per-issue rendering contexts without
    /// repeating whole-artifact validation.
    #[must_use]
    pub(crate) const fn from_validated(facts: ArtifactDbView<'a>) -> Self {
        Self { facts }
    }

    /// The validated fact view available to schema-owned renderers.
    #[must_use]
    pub(crate) const fn facts(&self) -> ArtifactDbView<'a> {
        self.facts
    }
}

/// One source label in a renderer-neutral diagnostic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RenderedLabel {
    pub(crate) anchor: RowRef,
    pub(crate) message: String,
}

/// The presentation selected for one typed provenance relation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RelationPresentation {
    pub(crate) summary: String,
    pub(crate) detail: Option<String>,
}

impl RelationPresentation {
    pub(crate) fn new(summary: impl Into<String>) -> Self {
        Self {
            summary: summary.into(),
            detail: None,
        }
    }

    pub(crate) fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

/// One selected trace relation paired with its schema-owned presentation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RenderedRelation {
    pub(crate) relation: RowRef,
    pub(crate) from: EntityRef,
    pub(crate) to: EntityRef,
    pub(crate) source: Option<EntityRef>,
    pub(crate) presentation: RelationPresentation,
}

/// Domain-neutral output of a registered issue renderer.
///
/// `data` carries the existing public JSON representation during migration.
/// Rustc emission remains an adapter concern so rendering cannot create or
/// satisfy obligations or perform new compiler probes.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RenderedDiagnostic {
    pub(crate) message: String,
    pub(crate) primary_anchor: Option<RowRef>,
    pub(crate) labels: Vec<RenderedLabel>,
    pub(crate) notes: Vec<String>,
    pub(crate) help: Vec<String>,
    pub(crate) trace: Vec<RenderedRelation>,
    pub(crate) data: Value,
    /// Stable schema-owned discriminator appended to generic report ordering.
    pub(crate) sort_key: Vec<String>,
}

impl RenderedDiagnostic {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            primary_anchor: None,
            labels: Vec::new(),
            notes: Vec::new(),
            help: Vec::new(),
            trace: Vec::new(),
            data: Value::Null,
            sort_key: Vec::new(),
        }
    }
}

/// Schema-owned formatter for one issue type.
pub(crate) trait IssueRenderer<I: IssueSchema> {
    fn render(&self, issue: &I, cx: &RenderCx<'_>) -> RenderedDiagnostic;
}

/// Schema-owned formatter for one provenance relation type.
pub(crate) trait RelationPresenter<R: RelationSchema> {
    fn present(&self, relation: &R, cx: &RenderCx<'_>) -> RelationPresentation;

    /// Presents a persisted relation with its generic provenance metadata.
    ///
    /// Existing payload-only presenters remain valid during migration. Packs
    /// that need endpoints or source provenance override this method.
    fn present_indexed(
        &self,
        relation: &R,
        metadata: &RelationIndexRow,
        cx: &RenderCx<'_>,
    ) -> RelationPresentation {
        let _ = metadata;
        self.present(relation, cx)
    }
}

/// Registration or serde-boundary failure in rendering infrastructure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RenderError {
    DuplicateIssueRenderer {
        schema: SchemaId,
    },
    DuplicateRelationPresenter {
        schema: SchemaId,
    },
    MissingIssueRenderer {
        schema: SchemaId,
    },
    InvalidArtifact {
        message: String,
    },
    SchemaContext {
        schema: SchemaId,
        expected: TableKind,
        message: String,
    },
    RelationLookup {
        relation: RowRef,
        message: String,
    },
    VersionMismatch {
        schema: SchemaId,
        registered: u32,
        encoded: u32,
    },
    Encode {
        schema: SchemaId,
        message: String,
    },
    Decode {
        schema: SchemaId,
        message: String,
    },
}

impl Display for RenderError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateIssueRenderer { schema } => {
                write!(formatter, "duplicate issue renderer for schema {schema:?}")
            }
            Self::DuplicateRelationPresenter { schema } => {
                write!(
                    formatter,
                    "duplicate relation presenter for schema {schema:?}"
                )
            }
            Self::MissingIssueRenderer { schema } => {
                write!(
                    formatter,
                    "no issue renderer is registered for schema {schema:?}"
                )
            }
            Self::InvalidArtifact { message } => {
                write!(formatter, "cannot render invalid artifact facts: {message}")
            }
            Self::SchemaContext {
                schema,
                expected,
                message,
            } => write!(
                formatter,
                "cannot render schema {schema:?} as {expected:?} in this analysis composition: {message}"
            ),
            Self::RelationLookup { relation, message } => write!(
                formatter,
                "cannot resolve relation `{}`:{} for rendering: {message}",
                relation.schema.as_str(),
                relation.row
            ),
            Self::VersionMismatch {
                schema,
                registered,
                encoded,
            } => write!(
                formatter,
                "renderer for schema {schema:?} expects version {registered}, but row has version {encoded}"
            ),
            Self::Encode { schema, message } => {
                write!(
                    formatter,
                    "could not encode schema {schema:?} for rendering: {message}"
                )
            }
            Self::Decode { schema, message } => {
                write!(
                    formatter,
                    "could not decode schema {schema:?} for rendering: {message}"
                )
            }
        }
    }
}

impl Error for RenderError {}

trait ErasedIssueRenderer {
    fn version(&self) -> u32;

    fn validate_context(&self, registry: &SchemaRegistry) -> Result<(), String>;

    fn render_value(&self, value: &Value, cx: &RenderCx<'_>) -> Result<RenderedDiagnostic, String>;
}

struct IssueRendererAdapter<I, R> {
    renderer: R,
    marker: PhantomData<fn() -> I>,
}

impl<I, R> ErasedIssueRenderer for IssueRendererAdapter<I, R>
where
    I: IssueSchema,
    R: IssueRenderer<I>,
{
    fn version(&self) -> u32 {
        I::VERSION
    }

    fn validate_context(&self, registry: &SchemaRegistry) -> Result<(), String> {
        validate_context_schema::<I>(registry, TableKind::Issue)
    }

    fn render_value(&self, value: &Value, cx: &RenderCx<'_>) -> Result<RenderedDiagnostic, String> {
        let issue =
            serde_json::from_value::<I>(value.clone()).map_err(|error| error.to_string())?;
        Ok(self.renderer.render(&issue, cx))
    }
}

trait ErasedRelationPresenter {
    fn version(&self) -> u32;

    fn validate_context(&self, registry: &SchemaRegistry) -> Result<(), String>;

    fn present_value(
        &self,
        value: &Value,
        cx: &RenderCx<'_>,
    ) -> Result<RelationPresentation, String>;

    fn present_indexed_value(
        &self,
        value: &Value,
        metadata: &RelationIndexRow,
        cx: &RenderCx<'_>,
    ) -> Result<RelationPresentation, String>;
}

struct RelationPresenterAdapter<R, P> {
    presenter: P,
    marker: PhantomData<fn() -> R>,
}

impl<R, P> ErasedRelationPresenter for RelationPresenterAdapter<R, P>
where
    R: RelationSchema,
    P: RelationPresenter<R>,
{
    fn version(&self) -> u32 {
        R::VERSION
    }

    fn validate_context(&self, registry: &SchemaRegistry) -> Result<(), String> {
        validate_context_schema::<R>(registry, TableKind::Relation)
    }

    fn present_value(
        &self,
        value: &Value,
        cx: &RenderCx<'_>,
    ) -> Result<RelationPresentation, String> {
        let relation =
            serde_json::from_value::<R>(value.clone()).map_err(|error| error.to_string())?;
        Ok(self.presenter.present(&relation, cx))
    }

    fn present_indexed_value(
        &self,
        value: &Value,
        metadata: &RelationIndexRow,
        cx: &RenderCx<'_>,
    ) -> Result<RelationPresentation, String> {
        let relation =
            serde_json::from_value::<R>(value.clone()).map_err(|error| error.to_string())?;
        Ok(self.presenter.present_indexed(&relation, metadata, cx))
    }
}

/// Heterogeneous renderer registry implemented solely with serde adapters.
#[derive(Default)]
pub(crate) struct RenderRegistry {
    issue_renderers: BTreeMap<SchemaId, Box<dyn ErasedIssueRenderer>>,
    relation_presenters: BTreeMap<SchemaId, Box<dyn ErasedRelationPresenter>>,
}

impl RenderRegistry {
    pub(crate) fn register_issue<I, R>(&mut self, renderer: R) -> Result<(), RenderError>
    where
        I: IssueSchema,
        R: IssueRenderer<I> + 'static,
    {
        let schema = stable_schema_id::<I>();
        if self.issue_renderers.contains_key(&schema) {
            return Err(RenderError::DuplicateIssueRenderer { schema });
        }
        self.issue_renderers.insert(
            schema,
            Box::new(IssueRendererAdapter::<I, R> {
                renderer,
                marker: PhantomData,
            }),
        );
        Ok(())
    }

    pub(crate) fn register_relation<R, P>(&mut self, presenter: P) -> Result<(), RenderError>
    where
        R: RelationSchema,
        P: RelationPresenter<R> + 'static,
    {
        let schema = stable_schema_id::<R>();
        if self.relation_presenters.contains_key(&schema) {
            return Err(RenderError::DuplicateRelationPresenter { schema });
        }
        self.relation_presenters.insert(
            schema,
            Box::new(RelationPresenterAdapter::<R, P> {
                presenter,
                marker: PhantomData,
            }),
        );
        Ok(())
    }

    pub(crate) fn render<I: IssueSchema>(
        &self,
        issue: &I,
        cx: &RenderCx<'_>,
    ) -> Result<RenderedDiagnostic, RenderError> {
        let schema = stable_schema_id::<I>();
        let value = serde_json::to_value(issue).map_err(|error| RenderError::Encode {
            schema: schema.clone(),
            message: error.to_string(),
        })?;
        self.render_value(&schema, I::VERSION, &value, cx)
    }

    /// Dispatches an encoded issue after its table has crossed the persistence
    /// or heterogeneous evaluation boundary.
    pub(crate) fn render_value(
        &self,
        schema: &SchemaId,
        version: u32,
        value: &Value,
        cx: &RenderCx<'_>,
    ) -> Result<RenderedDiagnostic, RenderError> {
        let renderer =
            self.issue_renderers
                .get(schema)
                .ok_or_else(|| RenderError::MissingIssueRenderer {
                    schema: schema.clone(),
                })?;
        validate_erased_context(
            schema,
            TableKind::Issue,
            renderer.validate_context(cx.facts().registry()),
        )?;
        validate_version(schema, renderer.version(), version)?;
        renderer
            .render_value(value, cx)
            .map_err(|message| RenderError::Decode {
                schema: schema.clone(),
                message,
            })
    }

    pub(crate) fn present<R: RelationSchema>(
        &self,
        relation: &R,
        cx: &RenderCx<'_>,
    ) -> Result<RelationPresentation, RenderError> {
        let schema = stable_schema_id::<R>();
        let value = serde_json::to_value(relation).map_err(|error| RenderError::Encode {
            schema: schema.clone(),
            message: error.to_string(),
        })?;
        self.present_value(&schema, R::VERSION, &value, cx)
    }

    /// Presents an encoded relation, falling back to its stable schema ID when
    /// no pack-specific presenter is installed. Unknown relations therefore
    /// remain useful in generic provenance traces.
    pub(crate) fn present_value(
        &self,
        schema: &SchemaId,
        version: u32,
        value: &Value,
        cx: &RenderCx<'_>,
    ) -> Result<RelationPresentation, RenderError> {
        let Some(presenter) = self.relation_presenters.get(schema) else {
            return Ok(RelationPresentation::new(format!(
                "relation {}",
                schema.as_str()
            )));
        };
        validate_erased_context(
            schema,
            TableKind::Relation,
            presenter.validate_context(cx.facts().registry()),
        )?;
        validate_version(schema, presenter.version(), version)?;
        presenter
            .present_value(value, cx)
            .map_err(|message| RenderError::Decode {
                schema: schema.clone(),
                message,
            })
    }

    /// Presents one persisted provenance edge selected by its canonical row ref.
    ///
    /// This is the authoritative relation-rendering entry point. It resolves
    /// the encoded payload and index metadata through the context's validated
    /// artifact view, then dispatches to the schema-owned presenter.
    pub(crate) fn present_relation(
        &self,
        relation: &RowRef,
        cx: &RenderCx<'_>,
    ) -> Result<RenderedRelation, RenderError> {
        let persisted = cx.facts().persisted_relation(relation).map_err(|error| {
            RenderError::RelationLookup {
                relation: relation.clone(),
                message: error.to_string(),
            }
        })?;
        self.present_persisted(persisted, cx)
    }

    /// Presents an already selected path in its supplied root-to-target order.
    pub(crate) fn present_path(
        &self,
        path: &[RowRef],
        cx: &RenderCx<'_>,
    ) -> Result<Vec<RenderedRelation>, RenderError> {
        path.iter()
            .map(|relation| {
                let persisted = cx.facts().persisted_relation(relation).map_err(|error| {
                    RenderError::RelationLookup {
                        relation: relation.clone(),
                        message: error.to_string(),
                    }
                })?;
                self.present_persisted(persisted, cx)
            })
            .collect()
    }

    fn present_persisted(
        &self,
        relation: PersistedRelation<'_>,
        cx: &RenderCx<'_>,
    ) -> Result<RenderedRelation, RenderError> {
        let reference = relation.reference().clone();
        let metadata = relation.metadata();
        let presentation = if let Some(presenter) = self.relation_presenters.get(&reference.schema)
        {
            validate_erased_context(
                &reference.schema,
                TableKind::Relation,
                presenter.validate_context(cx.facts().registry()),
            )?;
            validate_version(&reference.schema, presenter.version(), relation.version())?;
            presenter
                .present_indexed_value(relation.data(), metadata, cx)
                .map_err(|message| RenderError::Decode {
                    schema: reference.schema.clone(),
                    message,
                })?
        } else {
            RelationPresentation::new(format!("relation {}", reference.schema.as_str()))
        };

        Ok(RenderedRelation {
            relation: reference,
            from: metadata.from.clone(),
            to: metadata.to.clone(),
            source: metadata.source.clone(),
            presentation,
        })
    }

    pub(crate) fn has_issue_renderer(&self, schema: &SchemaId) -> bool {
        self.issue_renderers.contains_key(schema)
    }

    pub(crate) fn has_relation_presenter(&self, schema: &SchemaId) -> bool {
        self.relation_presenters.contains_key(schema)
    }
}

fn validate_version(schema: &SchemaId, registered: u32, encoded: u32) -> Result<(), RenderError> {
    if registered == encoded {
        Ok(())
    } else {
        Err(RenderError::VersionMismatch {
            schema: schema.clone(),
            registered,
            encoded,
        })
    }
}

fn validate_erased_context(
    schema: &SchemaId,
    expected: TableKind,
    validation: Result<(), String>,
) -> Result<(), RenderError> {
    validation.map_err(|message| RenderError::SchemaContext {
        schema: schema.clone(),
        expected,
        message,
    })
}

fn validate_context_schema<S: RowSchema>(
    registry: &SchemaRegistry,
    expected: TableKind,
) -> Result<(), String> {
    let descriptor = registry
        .descriptor_for::<S>()
        .map_err(|error| error.to_string())?;
    if descriptor.kind() != expected {
        return Err(format!(
            "registered table kind is {:?}, expected {expected:?}",
            descriptor.kind()
        ));
    }
    Ok(())
}

fn stable_schema_id<S: RowSchema>() -> SchemaId {
    SchemaId::new(S::ID).expect("registered row schemas must have valid stable schema IDs")
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use serde_json::json;

    use super::*;
    use crate::analysis::facts::encoded::{
        EncodedRow, EncodedTable, FACT_IR_FORMAT_VERSION, RelationIndexRow, TableKind,
    };
    use crate::analysis::facts::schema::EntitySchema;

    #[derive(Clone, Serialize, Deserialize)]
    struct Node(String);

    impl RowSchema for Node {
        const ID: &'static str = "sample.render.node";
        const VERSION: u32 = 1;
    }

    impl EntitySchema for Node {
        type Key = String;

        fn key(&self) -> Self::Key {
            self.0.clone()
        }
    }

    #[derive(Clone, Serialize, Deserialize)]
    struct SampleIssue {
        message: String,
    }

    impl RowSchema for SampleIssue {
        const ID: &'static str = "sample.render.issue";
        const VERSION: u32 = 3;
    }

    impl IssueSchema for SampleIssue {}

    struct SampleIssueRenderer;

    impl IssueRenderer<SampleIssue> for SampleIssueRenderer {
        fn render(&self, issue: &SampleIssue, _cx: &RenderCx<'_>) -> RenderedDiagnostic {
            let mut diagnostic = RenderedDiagnostic::new(&issue.message);
            diagnostic.data = json!({ "kind": "sample" });
            diagnostic
        }
    }

    #[derive(Clone, Serialize, Deserialize)]
    struct SampleRelation {
        reason: String,
    }

    impl RowSchema for SampleRelation {
        const ID: &'static str = "sample.render.relation";
        const VERSION: u32 = 1;
    }

    impl RelationSchema for SampleRelation {
        type From = Node;
        type To = Node;
    }

    struct SampleRelationPresenter;

    impl RelationPresenter<SampleRelation> for SampleRelationPresenter {
        fn present(&self, relation: &SampleRelation, _cx: &RenderCx<'_>) -> RelationPresentation {
            RelationPresentation::new("sample edge").with_detail(&relation.reason)
        }

        fn present_indexed(
            &self,
            relation: &SampleRelation,
            metadata: &RelationIndexRow,
            _cx: &RenderCx<'_>,
        ) -> RelationPresentation {
            RelationPresentation::new("sample edge").with_detail(format!(
                "{} ({} -> {})",
                relation.reason, metadata.from.row, metadata.to.row
            ))
        }
    }

    fn context<'a>(schemas: &'a SchemaRegistry, artifact: &'a ArtifactFactIr) -> RenderCx<'a> {
        RenderCx::open(artifact, schemas).expect("test artifacts must be valid rendering inputs")
    }

    fn empty_artifact() -> ArtifactFactIr {
        ArtifactFactIr {
            format_version: FACT_IR_FORMAT_VERSION,
            tables: Vec::new(),
            fact_index: Vec::new(),
            relation_index: Vec::new(),
        }
    }

    fn schema(id: &str) -> SchemaId {
        SchemaId::new(id).expect("valid test schema ID")
    }

    fn persisted_schemas() -> SchemaRegistry {
        let mut schemas = SchemaRegistry::new();
        schemas.register_entity::<Node>().unwrap();
        schemas.register_relation::<SampleRelation>().unwrap();
        schemas
    }

    fn issue_schemas() -> SchemaRegistry {
        let mut schemas = SchemaRegistry::new();
        schemas.register_issue::<SampleIssue>().unwrap();
        schemas
    }

    fn persisted_artifact() -> ArtifactFactIr {
        ArtifactFactIr {
            format_version: FACT_IR_FORMAT_VERSION,
            tables: vec![
                EncodedTable {
                    schema: schema(Node::ID),
                    version: Node::VERSION,
                    kind: TableKind::Entity,
                    rows: ["left", "middle", "right"]
                        .into_iter()
                        .map(|name| EncodedRow {
                            stable_key: Some(json!(name)),
                            data: json!(name),
                        })
                        .collect(),
                },
                EncodedTable {
                    schema: schema(SampleRelation::ID),
                    version: SampleRelation::VERSION,
                    kind: TableKind::Relation,
                    rows: ["first", "second"]
                        .into_iter()
                        .map(|reason| EncodedRow {
                            stable_key: None,
                            data: json!({ "reason": reason }),
                        })
                        .collect(),
                },
            ],
            fact_index: Vec::new(),
            relation_index: vec![
                RelationIndexRow {
                    relation: RowRef {
                        schema: schema(SampleRelation::ID),
                        row: 0,
                    },
                    from: EntityRef {
                        schema: schema(Node::ID),
                        row: 0,
                    },
                    to: EntityRef {
                        schema: schema(Node::ID),
                        row: 1,
                    },
                    source: Some(EntityRef {
                        schema: schema(Node::ID),
                        row: 0,
                    }),
                },
                RelationIndexRow {
                    relation: RowRef {
                        schema: schema(SampleRelation::ID),
                        row: 1,
                    },
                    from: EntityRef {
                        schema: schema(Node::ID),
                        row: 1,
                    },
                    to: EntityRef {
                        schema: schema(Node::ID),
                        row: 2,
                    },
                    source: None,
                },
            ],
        }
    }

    #[test]
    fn render_context_rejects_an_invalid_persisted_artifact() {
        let schemas = SchemaRegistry::new();
        let mut artifact = empty_artifact();
        artifact.format_version = 0;

        assert!(matches!(
            RenderCx::open(&artifact, &schemas),
            Err(RenderError::InvalidArtifact { .. })
        ));
    }

    #[test]
    fn render_context_reuses_an_already_validated_artifact_view() {
        let schemas = SchemaRegistry::new();
        let artifact = empty_artifact();
        let facts = ArtifactDbView::open(&artifact, &schemas).unwrap();

        let cx = RenderCx::from_validated(facts);

        assert!(std::ptr::eq(
            std::ptr::from_ref(cx.facts().artifact()),
            std::ptr::from_ref(&artifact),
        ));
        assert!(std::ptr::eq(
            std::ptr::from_ref(cx.facts().registry()),
            std::ptr::from_ref(&schemas),
        ));
    }

    #[test]
    fn issue_renderer_cannot_decode_a_schema_opaque_to_the_render_context() {
        let mut renderers = RenderRegistry::default();
        renderers
            .register_issue::<SampleIssue, _>(SampleIssueRenderer)
            .unwrap();
        let schemas = SchemaRegistry::new();
        let artifact = empty_artifact();

        let error = renderers
            .render(
                &SampleIssue {
                    message: "opaque issue".to_owned(),
                },
                &context(&schemas, &artifact),
            )
            .expect_err("the renderer's concrete issue schema must belong to the context");
        assert!(matches!(
            error,
            RenderError::SchemaContext {
                expected: TableKind::Issue,
                ..
            }
        ));
    }

    #[test]
    fn typed_presenter_cannot_decode_a_relation_opaque_to_the_render_context() {
        let mut renderers = RenderRegistry::default();
        renderers
            .register_relation::<SampleRelation, _>(SampleRelationPresenter)
            .unwrap();
        let schemas = SchemaRegistry::new();
        let artifact = persisted_artifact();
        let reference = RowRef {
            schema: schema(SampleRelation::ID),
            row: 0,
        };

        let error = renderers
            .present_relation(&reference, &context(&schemas, &artifact))
            .expect_err("an opaque relation must not cross into a typed presenter");
        assert!(matches!(
            error,
            RenderError::SchemaContext {
                expected: TableKind::Relation,
                ..
            }
        ));
    }

    #[test]
    fn typed_issue_renderer_dispatches_through_serde_without_downcasting() {
        let mut renderers = RenderRegistry::default();
        renderers
            .register_issue::<SampleIssue, _>(SampleIssueRenderer)
            .expect("register renderer");
        let schemas = issue_schemas();
        let artifact = empty_artifact();

        let rendered = renderers
            .render(
                &SampleIssue {
                    message: "sample failure".to_owned(),
                },
                &context(&schemas, &artifact),
            )
            .expect("render issue");

        assert_eq!(rendered.message, "sample failure");
        assert_eq!(rendered.data, json!({ "kind": "sample" }));
    }

    #[test]
    fn malformed_erased_issue_reports_schema_context() {
        let mut renderers = RenderRegistry::default();
        renderers
            .register_issue::<SampleIssue, _>(SampleIssueRenderer)
            .expect("register renderer");
        let schemas = issue_schemas();
        let artifact = empty_artifact();
        let schema = stable_schema_id::<SampleIssue>();

        let error = renderers
            .render_value(
                &schema,
                SampleIssue::VERSION,
                &json!({ "wrong": true }),
                &context(&schemas, &artifact),
            )
            .expect_err("malformed row must fail");

        assert!(matches!(error, RenderError::Decode { schema: found, .. } if found == schema));
    }

    #[test]
    fn relation_presenters_are_open_and_unknown_relations_have_a_fallback() {
        let mut renderers = RenderRegistry::default();
        renderers
            .register_relation::<SampleRelation, _>(SampleRelationPresenter)
            .expect("register presenter");
        let schemas = persisted_schemas();
        let artifact = empty_artifact();
        let cx = context(&schemas, &artifact);

        let known = renderers
            .present(
                &SampleRelation {
                    reason: "because".to_owned(),
                },
                &cx,
            )
            .expect("present known relation");
        let unknown_schema = SchemaId::new("future.pack.relation").unwrap();
        let unknown = renderers
            .present_value(&unknown_schema, 99, &json!({}), &cx)
            .expect("unknown relations remain presentable");

        assert_eq!(known.summary, "sample edge");
        assert_eq!(known.detail.as_deref(), Some("because"));
        assert_eq!(unknown.summary, "relation future.pack.relation");
    }

    #[test]
    fn persisted_relation_rendering_resolves_payload_endpoints_and_source() {
        let mut renderers = RenderRegistry::default();
        renderers
            .register_relation::<SampleRelation, _>(SampleRelationPresenter)
            .unwrap();
        let schemas = persisted_schemas();
        let artifact = persisted_artifact();
        let reference = RowRef {
            schema: schema(SampleRelation::ID),
            row: 0,
        };

        let rendered = renderers
            .present_relation(&reference, &context(&schemas, &artifact))
            .unwrap();

        assert_eq!(rendered.relation, reference);
        assert_eq!(rendered.from.row, 0);
        assert_eq!(rendered.to.row, 1);
        assert_eq!(rendered.source.unwrap().row, 0);
        assert_eq!(rendered.presentation.summary, "sample edge");
        assert_eq!(
            rendered.presentation.detail.as_deref(),
            Some("first (0 -> 1)")
        );
    }

    #[test]
    fn persisted_paths_preserve_selected_order_and_fallback_without_a_presenter() {
        let schemas = persisted_schemas();
        let artifact = persisted_artifact();
        let path = [0, 1]
            .into_iter()
            .map(|row| RowRef {
                schema: schema(SampleRelation::ID),
                row,
            })
            .collect::<Vec<_>>();

        let mut renderers = RenderRegistry::default();
        renderers
            .register_relation::<SampleRelation, _>(SampleRelationPresenter)
            .unwrap();
        let rendered = renderers
            .present_path(&path, &context(&schemas, &artifact))
            .unwrap();
        assert_eq!(
            rendered
                .iter()
                .map(|step| step.relation.row)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );

        let fallback = RenderRegistry::default()
            .present_relation(&path[0], &context(&schemas, &artifact))
            .unwrap();
        assert_eq!(
            fallback.presentation.summary,
            "relation sample.render.relation"
        );
    }

    #[test]
    fn duplicate_renderers_and_incompatible_versions_are_rejected() {
        let mut renderers = RenderRegistry::default();
        renderers
            .register_issue::<SampleIssue, _>(SampleIssueRenderer)
            .expect("register first renderer");
        assert!(matches!(
            renderers.register_issue::<SampleIssue, _>(SampleIssueRenderer),
            Err(RenderError::DuplicateIssueRenderer { .. })
        ));

        let schemas = issue_schemas();
        let artifact = empty_artifact();
        assert!(matches!(
            renderers.render_value(
                &stable_schema_id::<SampleIssue>(),
                2,
                &json!({ "message": "old" }),
                &context(&schemas, &artifact),
            ),
            Err(RenderError::VersionMismatch {
                registered: 3,
                encoded: 2,
                ..
            })
        ));
    }
}
