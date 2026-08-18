//! Typed presenters for ephemeral root-specific composition relations.
//!
//! Artifact presenters use an artifact-local `RenderCx`. Composition rows need
//! a different proof: an exact root-bound workspace, scoped endpoints, and the
//! composition schema registry that can decode the ephemeral payload. Keeping
//! this registry distinct prevents accidental artifact/context flattening.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::marker::PhantomData;

use super::{
    CompositionBuildError, CompositionRelationDb, CompositionRelationIndexRow,
    CompositionRelationRef, CompositionRelationRegistry, WorkspaceEvaluationView,
};
use crate::analysis::facts::render::RelationPresentation;
use crate::analysis::facts::schema::{CompositionRelationSchema, RowSchema, SchemaId};
use crate::analysis::facts::workspace::ScopedEntityRef;

/// Root/workspace proof made available to composition relation presenters.
pub(crate) struct CompositionRenderCx<'a> {
    evaluation: &'a WorkspaceEvaluationView<'a>,
    schemas: &'a CompositionRelationRegistry,
}

impl<'a> CompositionRenderCx<'a> {
    #[must_use]
    pub(crate) const fn open(
        evaluation: &'a WorkspaceEvaluationView<'a>,
        schemas: &'a CompositionRelationRegistry,
    ) -> Self {
        Self {
            evaluation,
            schemas,
        }
    }

    #[must_use]
    pub(crate) const fn evaluation(&self) -> &WorkspaceEvaluationView<'a> {
        self.evaluation
    }

    #[must_use]
    pub(crate) const fn schemas(&self) -> &CompositionRelationRegistry {
        self.schemas
    }

    const fn relations(&self) -> &CompositionRelationDb {
        self.evaluation.composition()
    }
}

/// Schema-owned formatter for one ephemeral composition relation type.
pub(crate) trait CompositionRelationPresenter<R: CompositionRelationSchema> {
    fn present(
        &self,
        relation: &R,
        metadata: &CompositionRelationIndexRow,
        cx: &CompositionRenderCx<'_>,
    ) -> RelationPresentation;
}

trait ErasedCompositionRelationPresenter {
    fn present(
        &self,
        reference: &CompositionRelationRef,
        metadata: &CompositionRelationIndexRow,
        cx: &CompositionRenderCx<'_>,
    ) -> Result<RelationPresentation, String>;
}

struct CompositionPresenterAdapter<R, P> {
    presenter: P,
    marker: PhantomData<fn() -> R>,
}

impl<R, P> ErasedCompositionRelationPresenter for CompositionPresenterAdapter<R, P>
where
    R: CompositionRelationSchema,
    P: CompositionRelationPresenter<R>,
{
    fn present(
        &self,
        reference: &CompositionRelationRef,
        metadata: &CompositionRelationIndexRow,
        cx: &CompositionRenderCx<'_>,
    ) -> Result<RelationPresentation, String> {
        let relation = cx
            .relations()
            .relation::<R>(reference, cx.schemas())
            .map_err(|error| error.to_string())?;
        Ok(self.presenter.present(&relation.data, metadata, cx))
    }
}

/// One scoped composition edge paired with its schema-owned presentation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RenderedCompositionRelation {
    pub(crate) relation: CompositionRelationRef,
    pub(crate) from: ScopedEntityRef,
    pub(crate) to: ScopedEntityRef,
    pub(crate) source: Option<ScopedEntityRef>,
    pub(crate) presentation: RelationPresentation,
}

/// Heterogeneous compile-time presenter registry for composition relations.
#[derive(Default)]
pub(crate) struct CompositionRenderRegistry {
    presenters: BTreeMap<SchemaId, Box<dyn ErasedCompositionRelationPresenter>>,
}

impl CompositionRenderRegistry {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn register<R, P>(
        &mut self,
        schemas: &CompositionRelationRegistry,
        presenter: P,
    ) -> Result<(), CompositionRenderError>
    where
        R: CompositionRelationSchema,
        P: CompositionRelationPresenter<R> + 'static,
    {
        let descriptor = schemas.descriptor_for::<R>().map_err(|error| {
            CompositionRenderError::SchemaContext {
                schema: stable_schema_id::<R>(),
                message: error.to_string(),
            }
        })?;
        let schema = descriptor.id().clone();
        if self.presenters.contains_key(&schema) {
            return Err(CompositionRenderError::DuplicatePresenter { schema });
        }
        self.presenters.insert(
            schema,
            Box::new(CompositionPresenterAdapter::<R, P> {
                presenter,
                marker: PhantomData,
            }),
        );
        Ok(())
    }

    pub(crate) fn present_relation(
        &self,
        reference: &CompositionRelationRef,
        cx: &CompositionRenderCx<'_>,
    ) -> Result<RenderedCompositionRelation, CompositionRenderError> {
        let metadata = composition_metadata(cx.relations(), reference)?;
        let presentation = if let Some(presenter) = self.presenters.get(&reference.schema) {
            presenter
                .present(reference, metadata, cx)
                .map_err(|message| CompositionRenderError::Decode {
                    relation: reference.clone(),
                    message,
                })?
        } else {
            RelationPresentation::new(format!("relation {}", reference.schema.as_str()))
        };
        Ok(RenderedCompositionRelation {
            relation: reference.clone(),
            from: metadata.from.clone(),
            to: metadata.to.clone(),
            source: metadata.source.clone(),
            presentation,
        })
    }

    pub(crate) fn present_path(
        &self,
        path: &[CompositionRelationRef],
        cx: &CompositionRenderCx<'_>,
    ) -> Result<Vec<RenderedCompositionRelation>, CompositionRenderError> {
        path.iter()
            .map(|reference| self.present_relation(reference, cx))
            .collect()
    }

    #[must_use]
    pub(crate) fn has_presenter(&self, schema: &SchemaId) -> bool {
        self.presenters.contains_key(schema)
    }
}

fn composition_metadata<'a>(
    relations: &'a CompositionRelationDb,
    reference: &CompositionRelationRef,
) -> Result<&'a CompositionRelationIndexRow, CompositionRenderError> {
    relations
        .relation_index
        .binary_search_by(|row| row.relation.cmp(reference))
        .ok()
        .map(|index| &relations.relation_index[index])
        .ok_or_else(|| CompositionRenderError::RelationLookup {
            relation: reference.clone(),
            message: CompositionBuildError::MissingIndex {
                reference: reference.clone(),
            }
            .to_string(),
        })
}

fn stable_schema_id<S: RowSchema>() -> SchemaId {
    SchemaId::new(S::ID).expect("registered composition schemas have valid stable IDs")
}

/// Structured composition-presenter registration or dispatch failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CompositionRenderError {
    DuplicatePresenter {
        schema: SchemaId,
    },
    SchemaContext {
        schema: SchemaId,
        message: String,
    },
    RelationLookup {
        relation: CompositionRelationRef,
        message: String,
    },
    Decode {
        relation: CompositionRelationRef,
        message: String,
    },
}

impl Display for CompositionRenderError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicatePresenter { schema } => {
                write!(formatter, "duplicate composition presenter for `{schema}`")
            }
            Self::SchemaContext { schema, message } => write!(
                formatter,
                "composition presenter schema `{schema}` is unavailable: {message}"
            ),
            Self::RelationLookup { relation, message } => write!(
                formatter,
                "cannot resolve composition relation `{}`:{}: {message}",
                relation.schema, relation.row
            ),
            Self::Decode { relation, message } => write!(
                formatter,
                "cannot present composition relation `{}`:{}: {message}",
                relation.schema, relation.row
            ),
        }
    }
}

impl Error for CompositionRenderError {}
