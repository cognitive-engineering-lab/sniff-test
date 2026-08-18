//! Guarded typed inputs and isolated outputs for one evaluation rule.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;

use super::super::composition::WorkspaceRelationGraph;
use super::super::encoded::TableKind;
use super::super::registry::SchemaRegistry;
use super::super::schema::{
    DerivedSchema, EntitySchema, FactSchema, IssueSchema, PassId, RelationSchema,
    RequirementSchema, RowSchema, SchemaId, canonical_json_bytes, encode_row,
};
use super::super::view::{ArtifactDbView, IndexedRow, TypedFact, TypedRelation};
use super::super::workspace::{
    ArtifactScopeId, ScopedEntityRef, ScopedRowRef, WorkspaceFactView, WorkspaceIdentity,
};
use super::model::{EvaluationIssueContext, EvaluationRoot, ObligationRecord, RelationTrace};
use super::scheduler::RuleDescriptor;
use super::store::{EvaluationDb, EvaluationStorageError, validate_registered_kind};

/// Compiler- and workspace-specific services available to evaluation rules.
pub(crate) struct EvaluationCx<'a, C: ?Sized> {
    root: &'a EvaluationRoot,
    services: &'a C,
}

impl<'a, C: ?Sized> EvaluationCx<'a, C> {
    pub(super) const fn new(root: &'a EvaluationRoot, services: &'a C) -> Self {
        Self { root, services }
    }

    #[must_use]
    pub(crate) const fn root(&self) -> &'a EvaluationRoot {
        self.root
    }

    #[must_use]
    pub(crate) const fn services(&self) -> &'a C {
        self.services
    }
}

/// One committed issue made available as typed input to a later rule.
#[derive(Clone, Debug)]
pub(crate) struct EvaluatedIssueInput<I: IssueSchema> {
    pub(crate) data: I,
    pub(crate) context: EvaluationIssueContext,
    pub(crate) producer: PassId,
}

/// One committed derived row made available as typed input to a later rule.
#[derive(Clone, Debug)]
pub(crate) struct DerivedRowInput<D: DerivedSchema> {
    pub(crate) data: D,
    pub(crate) root: EvaluationRoot,
    pub(crate) producer: PassId,
}

/// Guarded immutable inputs for one active evaluation rule.
pub(crate) struct EvaluationInput<'a> {
    rule: &'a PassId,
    declared_reads: &'a BTreeSet<SchemaId>,
    artifact: ArtifactDbView<'a>,
    workspace: &'a WorkspaceFactView<'a>,
    evaluated: &'a EvaluationDb,
    registry: &'a SchemaRegistry,
}

impl EvaluationInput<'_> {
    pub(super) const fn new<'a>(
        rule: &'a PassId,
        declared_reads: &'a BTreeSet<SchemaId>,
        artifact: ArtifactDbView<'a>,
        workspace: &'a WorkspaceFactView<'a>,
        evaluated: &'a EvaluationDb,
        registry: &'a SchemaRegistry,
    ) -> EvaluationInput<'a> {
        EvaluationInput {
            rule,
            declared_reads,
            artifact,
            workspace,
            evaluated,
            registry,
        }
    }

    /// Checks whether an in-memory prepared input belongs to this exact workspace view.
    pub(in crate::analysis::facts) fn has_workspace_identity(
        &self,
        identity: &Arc<WorkspaceIdentity>,
    ) -> bool {
        self.workspace.has_identity(identity)
    }

    /// Reads an artifact table through its registered concrete row type.
    pub(crate) fn artifact_rows<S: RowSchema>(&self) -> Result<Vec<IndexedRow<S>>, RuleError> {
        let schema = self.authorize_read::<S>()?;
        let descriptor =
            self.registry
                .descriptor_for::<S>()
                .map_err(|error| RuleError::Registry {
                    rule: self.rule.clone(),
                    schema: schema.clone(),
                    reason: error.to_string(),
                })?;
        if matches!(descriptor.kind(), TableKind::Derived | TableKind::Issue) {
            return Err(RuleError::WrongInputKind {
                rule: self.rule.clone(),
                schema,
                expected: "artifact entity, fact, relation, or requirement",
                found: descriptor.kind(),
            });
        }
        self.artifact
            .indexed_rows::<S>()
            .map_err(|error| RuleError::ArtifactRead {
                rule: self.rule.clone(),
                schema,
                reason: error.to_string(),
            })
    }

    /// Reads compiler or human facts together with owner, anchor, provenance,
    /// producer, and typed requirement references from the generic fact index.
    pub(crate) fn artifact_facts<F: FactSchema>(&self) -> Result<Vec<TypedFact<F>>, RuleError> {
        let schema = self.authorize_read::<F>()?;
        self.expect_input_kind::<F>(&schema, TableKind::Fact, "artifact fact")?;
        self.artifact
            .facts::<F>()
            .map_err(|error| RuleError::ArtifactRead {
                rule: self.rule.clone(),
                schema,
                reason: error.to_string(),
            })
    }

    /// Reads one compiler or human fact from its exact managed artifact scope.
    ///
    /// The returned fact metadata remains artifact-local; callers use the
    /// supplied scoped reference when promoting owners, anchors, and
    /// requirements into workspace evaluation rows.
    pub(crate) fn artifact_fact_at<F: FactSchema>(
        &self,
        reference: &ScopedRowRef,
    ) -> Result<TypedFact<F>, RuleError> {
        let schema = self.authorize_read::<F>()?;
        self.expect_input_kind::<F>(&schema, TableKind::Fact, "artifact fact")?;
        self.workspace
            .fact::<F>(reference)
            .map_err(|error| RuleError::ArtifactRead {
                rule: self.rule.clone(),
                schema,
                reason: error.to_string(),
            })
    }

    /// Reads one entity from its exact managed artifact scope.
    pub(crate) fn artifact_entity_at<E: EntitySchema>(
        &self,
        reference: &ScopedEntityRef,
    ) -> Result<E, RuleError> {
        let schema = self.authorize_read::<E>()?;
        self.expect_input_kind::<E>(&schema, TableKind::Entity, "artifact entity")?;
        self.workspace
            .entity::<E>(reference)
            .map_err(|error| RuleError::ArtifactRead {
                rule: self.rule.clone(),
                schema,
                reason: error.to_string(),
            })
    }

    /// Looks up one typed entity key in its exact managed artifact scope.
    pub(crate) fn artifact_entity_by_key<E: EntitySchema>(
        &self,
        scope: &ArtifactScopeId,
        key: &E::Key,
    ) -> Result<Option<ScopedEntityRef>, RuleError> {
        let schema = self.authorize_read::<E>()?;
        self.expect_input_kind::<E>(&schema, TableKind::Entity, "artifact entity")?;
        self.workspace
            .entity_by_key::<E>(scope, key)
            .map_err(|error| RuleError::ArtifactRead {
                rule: self.rule.clone(),
                schema,
                reason: error.to_string(),
            })
    }

    /// Reads one typed requirement from its exact managed artifact scope.
    pub(crate) fn artifact_requirement_at<R: RequirementSchema>(
        &self,
        reference: &ScopedRowRef,
    ) -> Result<R, RuleError> {
        let schema = self.authorize_read::<R>()?;
        self.expect_input_kind::<R>(&schema, TableKind::Requirement, "artifact requirement")?;
        self.workspace
            .row::<R>(reference)
            .map(|row| row.data)
            .map_err(|error| RuleError::ArtifactRead {
                rule: self.rule.clone(),
                schema,
                reason: error.to_string(),
            })
    }

    /// Reads typed relation payloads with validated typed endpoints and source.
    pub(crate) fn artifact_relations<R: RelationSchema>(
        &self,
    ) -> Result<Vec<TypedRelation<R>>, RuleError> {
        let schema = self.authorize_read::<R>()?;
        self.expect_input_kind::<R>(&schema, TableKind::Relation, "artifact relation")?;
        self.artifact
            .relations::<R>()
            .map_err(|error| RuleError::ArtifactRead {
                rule: self.rule.clone(),
                schema,
                reason: error.to_string(),
            })
    }

    /// Reads typed issues committed by an earlier rule in this root evaluation.
    pub(crate) fn issues<I: IssueSchema>(&self) -> Result<Vec<EvaluatedIssueInput<I>>, RuleError> {
        let schema = self.authorize_read::<I>()?;
        validate_registered_kind::<I>(self.registry, TableKind::Issue).map_err(|error| {
            RuleError::Registry {
                rule: self.rule.clone(),
                schema,
                reason: error.to_string(),
            }
        })?;
        self.evaluated
            .pending_issues::<I>(self.registry)
            .map(|rows| {
                rows.into_iter()
                    .map(|row| {
                        let (data, context, producer) = row.into_parts();
                        EvaluatedIssueInput {
                            data,
                            context,
                            producer,
                        }
                    })
                    .collect()
            })
            .map_err(|error| RuleError::Storage {
                rule: self.rule.clone(),
                source: error,
            })
    }

    /// Reads typed root-specific rows committed by an earlier evaluation rule.
    pub(crate) fn derived_rows<D: DerivedSchema>(
        &self,
    ) -> Result<Vec<DerivedRowInput<D>>, RuleError> {
        let schema = self.authorize_read::<D>()?;
        validate_registered_kind::<D>(self.registry, TableKind::Derived).map_err(|error| {
            RuleError::Registry {
                rule: self.rule.clone(),
                schema,
                reason: error.to_string(),
            }
        })?;
        self.evaluated
            .pending_derived::<D>(self.registry)
            .map(|rows| {
                rows.into_iter()
                    .map(|row| {
                        let (data, root, producer) = row.into_parts();
                        DerivedRowInput {
                            data,
                            root,
                            producer,
                        }
                    })
                    .collect()
            })
            .map_err(|error| RuleError::Storage {
                rule: self.rule.clone(),
                source: error,
            })
    }

    fn authorize_read<S: RowSchema>(&self) -> Result<SchemaId, RuleError> {
        let schema = SchemaId::new(S::ID).map_err(|error| RuleError::InvalidSchema {
            rule: self.rule.clone(),
            declared: S::ID,
            reason: error.to_string(),
        })?;
        if !self.declared_reads.contains(&schema) {
            return Err(RuleError::UndeclaredRead {
                rule: self.rule.clone(),
                schema,
            });
        }
        self.registry
            .descriptor_for::<S>()
            .map_err(|error| RuleError::Registry {
                rule: self.rule.clone(),
                schema: schema.clone(),
                reason: error.to_string(),
            })?;
        Ok(schema)
    }

    fn expect_input_kind<S: RowSchema>(
        &self,
        schema: &SchemaId,
        expected: TableKind,
        label: &'static str,
    ) -> Result<(), RuleError> {
        let descriptor =
            self.registry
                .descriptor_for::<S>()
                .map_err(|error| RuleError::Registry {
                    rule: self.rule.clone(),
                    schema: schema.clone(),
                    reason: error.to_string(),
                })?;
        if descriptor.kind() != expected {
            return Err(RuleError::WrongInputKind {
                rule: self.rule.clone(),
                schema: schema.clone(),
                expected: label,
                found: descriptor.kind(),
            });
        }
        Ok(())
    }
}

/// Isolated, issue-only delta exposed to one active evaluation rule.
pub(crate) struct EvaluationOutput<'a> {
    rule: &'a PassId,
    root: &'a EvaluationRoot,
    declared_writes: &'a BTreeSet<SchemaId>,
    delta: &'a mut EvaluationDb,
    registry: &'a SchemaRegistry,
    references: &'a dyn EvaluationReferenceValidator,
}

impl EvaluationOutput<'_> {
    pub(super) fn new<'a>(
        rule: &'a PassId,
        root: &'a EvaluationRoot,
        declared_writes: &'a BTreeSet<SchemaId>,
        delta: &'a mut EvaluationDb,
        registry: &'a SchemaRegistry,
        references: &'a dyn EvaluationReferenceValidator,
    ) -> EvaluationOutput<'a> {
        EvaluationOutput {
            rule,
            root,
            declared_writes,
            delta,
            registry,
            references,
        }
    }

    pub(crate) fn emit_issue<I: IssueSchema>(
        &mut self,
        issue: &I,
        context: EvaluationIssueContext,
    ) -> Result<(), RuleError> {
        let schema = SchemaId::new(I::ID).map_err(|error| RuleError::InvalidSchema {
            rule: self.rule.clone(),
            declared: I::ID,
            reason: error.to_string(),
        })?;
        if !self.declared_writes.contains(&schema) {
            return Err(RuleError::UndeclaredWrite {
                rule: self.rule.clone(),
                schema,
            });
        }
        validate_registered_kind::<I>(self.registry, TableKind::Issue).map_err(|error| {
            RuleError::Registry {
                rule: self.rule.clone(),
                schema: schema.clone(),
                reason: error.to_string(),
            }
        })?;
        self.validate_issue_context(&context)?;
        let data = encode_row(issue).map_err(|error| RuleError::Storage {
            rule: self.rule.clone(),
            source: EvaluationStorageError::Codec(error.to_string()),
        })?;
        let data_bytes =
            canonical_json_bytes(I::ID, &data).map_err(|error| RuleError::Storage {
                rule: self.rule.clone(),
                source: EvaluationStorageError::Codec(error.to_string()),
            })?;
        self.delta
            .push_issue(
                schema,
                I::VERSION,
                data,
                data_bytes,
                context,
                self.rule.clone(),
            )
            .map_err(|source| RuleError::Storage {
                rule: self.rule.clone(),
                source,
            })
    }

    pub(crate) fn emit_obligation(
        &mut self,
        obligation: &ObligationRecord,
    ) -> Result<(), RuleError> {
        if obligation.domain() != &self.root.domain {
            return Err(self.invalid_reference("obligation domain does not match the active root"));
        }
        if obligation.trace().root() != &self.root.entity {
            return Err(
                self.invalid_reference("obligation trace does not start at the active root")
            );
        }
        if obligation.trace().target() != obligation.trace_target() {
            return Err(self.invalid_reference("obligation trace target is inconsistent"));
        }
        self.references
            .validate_row(obligation.source(), None)
            .map_err(|reason| self.invalid_reference(reason))?;
        self.references
            .validate_entity(obligation.endpoint())
            .map_err(|reason| self.invalid_reference(reason))?;
        self.references
            .validate_entity(obligation.trace_target())
            .map_err(|reason| self.invalid_reference(reason))?;
        for requirement in obligation.requirements() {
            self.references
                .validate_row(requirement, Some(TableKind::Requirement))
                .map_err(|reason| self.invalid_reference(reason))?;
        }
        self.references
            .validate_trace(obligation.trace())
            .map_err(|reason| self.invalid_reference(reason))?;
        self.emit_derived(obligation)
    }

    /// Validates one scoped row supplied by a linker or composition rule.
    pub(crate) fn validate_row_reference(
        &self,
        reference: &ScopedRowRef,
        expected: Option<TableKind>,
    ) -> Result<(), RuleError> {
        self.references
            .validate_row(reference, expected)
            .map_err(|reason| self.invalid_reference(reason))
    }

    /// Validates one scoped semantic endpoint supplied by a linker rule.
    pub(crate) fn validate_entity_reference(
        &self,
        reference: &ScopedEntityRef,
    ) -> Result<(), RuleError> {
        self.references
            .validate_entity(reference)
            .map_err(|reason| self.invalid_reference(reason))
    }

    /// Validates an exact root-scoped provenance path before it is committed.
    pub(crate) fn validate_relation_trace(&self, trace: &RelationTrace) -> Result<(), RuleError> {
        if trace.root() != &self.root.entity {
            return Err(self
                .invalid_reference("derived trace does not start at the active evaluation root"));
        }
        self.references
            .validate_trace(trace)
            .map_err(|reason| self.invalid_reference(reason))
    }

    /// Emits one typed root-scoped intermediate row into this rule's delta.
    pub(crate) fn emit_derived<D: DerivedSchema>(&mut self, derived: &D) -> Result<(), RuleError> {
        let schema = SchemaId::new(D::ID).map_err(|error| RuleError::InvalidSchema {
            rule: self.rule.clone(),
            declared: D::ID,
            reason: error.to_string(),
        })?;
        if !self.declared_writes.contains(&schema) {
            return Err(RuleError::UndeclaredWrite {
                rule: self.rule.clone(),
                schema,
            });
        }
        validate_registered_kind::<D>(self.registry, TableKind::Derived).map_err(|error| {
            RuleError::Registry {
                rule: self.rule.clone(),
                schema: schema.clone(),
                reason: error.to_string(),
            }
        })?;
        let data = encode_row(derived).map_err(|error| RuleError::Storage {
            rule: self.rule.clone(),
            source: EvaluationStorageError::Codec(error.to_string()),
        })?;
        let data_bytes =
            canonical_json_bytes(D::ID, &data).map_err(|error| RuleError::Storage {
                rule: self.rule.clone(),
                source: EvaluationStorageError::Codec(error.to_string()),
            })?;
        self.delta
            .push_derived(
                schema,
                D::VERSION,
                data,
                data_bytes,
                self.root.clone(),
                self.rule.clone(),
            )
            .map_err(|source| RuleError::Storage {
                rule: self.rule.clone(),
                source,
            })
    }

    fn validate_issue_context(&self, context: &EvaluationIssueContext) -> Result<(), RuleError> {
        if context.root != *self.root {
            return Err(self.invalid_reference("issue context does not match the active root"));
        }
        if let Some(source) = &context.source {
            self.references
                .validate_row(source, None)
                .map_err(|reason| self.invalid_reference(reason))?;
        }
        if let Some(endpoint) = &context.endpoint {
            self.references
                .validate_entity(endpoint)
                .map_err(|reason| self.invalid_reference(reason))?;
        }
        if let Some(trace) = &context.trace {
            if trace.root() != &self.root.entity {
                return Err(self.invalid_reference("issue trace does not start at the active root"));
            }
            self.references
                .validate_trace(trace)
                .map_err(|reason| self.invalid_reference(reason))?;
        }
        Ok(())
    }

    fn invalid_reference(&self, reason: impl Into<String>) -> RuleError {
        RuleError::InvalidReference {
            rule: self.rule.clone(),
            reason: reason.into(),
        }
    }
}

pub(super) trait EvaluationReferenceValidator {
    fn validate_row(
        &self,
        reference: &ScopedRowRef,
        expected: Option<TableKind>,
    ) -> Result<(), String>;

    fn validate_entity(&self, reference: &ScopedEntityRef) -> Result<(), String>;

    fn validate_trace(&self, trace: &RelationTrace) -> Result<(), String>;
}

/// The one authoritative reference validator used by evaluation rules.
pub(super) struct WorkspaceLookup<'a> {
    facts: &'a WorkspaceFactView<'a>,
    graph: &'a WorkspaceRelationGraph,
}

impl<'a> WorkspaceLookup<'a> {
    pub(super) const fn new(
        facts: &'a WorkspaceFactView<'a>,
        graph: &'a WorkspaceRelationGraph,
    ) -> Self {
        Self { facts, graph }
    }
}

impl EvaluationReferenceValidator for WorkspaceLookup<'_> {
    fn validate_row(
        &self,
        reference: &ScopedRowRef,
        expected: Option<TableKind>,
    ) -> Result<(), String> {
        self.facts
            .validate_erased_row(reference, expected)
            .map_err(|error| error.to_string())
    }

    fn validate_entity(&self, reference: &ScopedEntityRef) -> Result<(), String> {
        self.facts
            .validate_entity(reference)
            .map_err(|error| error.to_string())
    }

    fn validate_trace(&self, trace: &RelationTrace) -> Result<(), String> {
        self.graph
            .validate_path(trace.root(), trace.target(), trace.relations())
            .map(drop)
            .map_err(|error| error.to_string())
    }
}

/// One compile-time root-specific derived-analysis pass.
pub(crate) trait EvaluationRule<C: ?Sized> {
    fn descriptor(&self) -> RuleDescriptor;

    fn evaluate(
        &self,
        cx: &EvaluationCx<'_, C>,
        input: &EvaluationInput<'_>,
        output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError>;
}

/// A structured failure produced by one active evaluation rule.
#[derive(Debug)]
pub(crate) enum RuleError {
    InvalidSchema {
        rule: PassId,
        declared: &'static str,
        reason: String,
    },
    UndeclaredRead {
        rule: PassId,
        schema: SchemaId,
    },
    UndeclaredWrite {
        rule: PassId,
        schema: SchemaId,
    },
    Registry {
        rule: PassId,
        schema: SchemaId,
        reason: String,
    },
    WrongInputKind {
        rule: PassId,
        schema: SchemaId,
        expected: &'static str,
        found: TableKind,
    },
    ArtifactRead {
        rule: PassId,
        schema: SchemaId,
        reason: String,
    },
    MissingArtifactInput {
        rule: PassId,
        schema: SchemaId,
    },
    InvalidReference {
        rule: PassId,
        reason: String,
    },
    Storage {
        rule: PassId,
        source: EvaluationStorageError,
    },
    Failed {
        message: String,
    },
}

impl RuleError {
    pub(crate) fn failed(message: impl Into<String>) -> Self {
        Self::Failed {
            message: message.into(),
        }
    }
}

impl Display for RuleError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSchema {
                rule,
                declared,
                reason,
            } => write!(
                formatter,
                "evaluation rule {rule} used invalid schema ID {declared:?}: {reason}"
            ),
            Self::UndeclaredRead { rule, schema } => {
                write!(
                    formatter,
                    "evaluation rule {rule} attempted undeclared read of {schema}"
                )
            }
            Self::UndeclaredWrite { rule, schema } => write!(
                formatter,
                "evaluation rule {rule} attempted undeclared issue write to {schema}"
            ),
            Self::Registry {
                rule,
                schema,
                reason,
            } => write!(
                formatter,
                "evaluation rule {rule} cannot use schema {schema}: {reason}"
            ),
            Self::WrongInputKind {
                rule,
                schema,
                expected,
                found,
            } => write!(
                formatter,
                "evaluation rule {rule} read {found:?} schema {schema} as {expected}"
            ),
            Self::ArtifactRead {
                rule,
                schema,
                reason,
            } => write!(
                formatter,
                "evaluation rule {rule} could not read artifact schema {schema}: {reason}"
            ),
            Self::MissingArtifactInput { rule, schema } => write!(
                formatter,
                "evaluation rule {rule} requires artifact schema {schema}, but the selected artifact has no such table"
            ),
            Self::InvalidReference { rule, reason } => {
                write!(
                    formatter,
                    "evaluation rule {rule} emitted invalid context: {reason}"
                )
            }
            Self::Storage { rule, source } => {
                write!(
                    formatter,
                    "evaluation rule {rule} could not store output: {source}"
                )
            }
            Self::Failed { message } => formatter.write_str(message),
        }
    }
}

impl Error for RuleError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Storage { source, .. } => Some(source),
            _ => None,
        }
    }
}
