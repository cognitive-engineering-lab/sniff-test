//! Typed, canonical storage for root-specific derived rows and issues.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::super::encoded::{EncodedRow, EncodedTable, RowRef, TableKind};
use super::super::registry::SchemaRegistry;
use super::super::schema::{DerivedSchema, IssueSchema, PassId, RowSchema, SchemaId, decode_row};
use super::model::{EvaluationIssueContext, EvaluationRoot};

/// Generic metadata stored beside one finalized root-specific derived row.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct DerivedIndexRow {
    pub(crate) derived: RowRef,
    pub(crate) root: EvaluationRoot,
    pub(crate) producer: PassId,
}

/// One finalized derived row decoded through its registered schema.
#[derive(Clone, Debug)]
pub(crate) struct TypedDerivedRow<D: DerivedSchema> {
    pub(crate) reference: RowRef,
    pub(crate) data: D,
    pub(crate) root: EvaluationRoot,
    pub(crate) producer: PassId,
}

/// Generic context stored beside one finalized typed issue row.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct EvaluatedIssueIndexRow {
    pub(crate) issue: RowRef,
    pub(crate) context: EvaluationIssueContext,
    pub(crate) producer: PassId,
}

/// One finalized issue decoded through its registered schema.
#[derive(Clone, Debug)]
pub(crate) struct TypedEvaluatedIssue<I: IssueSchema> {
    pub(crate) reference: RowRef,
    pub(crate) data: I,
    pub(crate) context: EvaluationIssueContext,
    pub(crate) producer: PassId,
}

#[derive(Clone, Debug)]
struct PendingIssue {
    data: Value,
    data_bytes: Vec<u8>,
    context: EvaluationIssueContext,
    producer: PassId,
}

#[derive(Clone, Debug)]
struct PendingIssueTable {
    version: u32,
    rows: Vec<PendingIssue>,
}

#[derive(Clone, Debug)]
struct PendingDerived {
    data: Value,
    data_bytes: Vec<u8>,
    root: EvaluationRoot,
    producer: PassId,
}

#[derive(Clone, Debug)]
struct PendingDerivedTable {
    version: u32,
    rows: Vec<PendingDerived>,
}

/// Committed root-specific results visible to later rules.
///
/// It is deliberately separate from [`ArtifactFactIr`]. Evaluation never gains
/// a mutable artifact handle, and a failed rule's isolated delta is discarded.
#[derive(Clone, Debug, Default)]
pub(crate) struct EvaluationDb {
    issue_tables: BTreeMap<SchemaId, PendingIssueTable>,
    derived_tables: BTreeMap<SchemaId, PendingDerivedTable>,
}

impl EvaluationDb {
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            issue_tables: BTreeMap::new(),
            derived_tables: BTreeMap::new(),
        }
    }

    #[must_use]
    pub(crate) fn issue_count(&self) -> usize {
        self.issue_tables
            .values()
            .map(|table| table.rows.len())
            .sum()
    }

    #[must_use]
    pub(crate) fn derived_count(&self) -> usize {
        self.derived_tables
            .values()
            .map(|table| table.rows.len())
            .sum()
    }

    pub(super) fn incompatible_root(&self, expected: &EvaluationRoot) -> Option<EvaluationRoot> {
        self.issue_tables
            .values()
            .flat_map(|table| &table.rows)
            .map(|issue| &issue.context.root)
            .find(|root| *root != expected)
            .cloned()
            .or_else(|| {
                self.derived_tables
                    .values()
                    .flat_map(|table| &table.rows)
                    .map(|derived| &derived.root)
                    .find(|root| *root != expected)
                    .cloned()
            })
    }

    pub(super) fn push_issue(
        &mut self,
        schema: SchemaId,
        version: u32,
        data: Value,
        data_bytes: Vec<u8>,
        context: EvaluationIssueContext,
        producer: PassId,
    ) -> Result<(), EvaluationStorageError> {
        let table = self
            .issue_tables
            .entry(schema.clone())
            .or_insert_with(|| PendingIssueTable {
                version,
                rows: Vec::new(),
            });
        if table.version != version {
            return Err(EvaluationStorageError::VersionConflict {
                schema,
                existing: table.version,
                incoming: version,
            });
        }
        table.rows.push(PendingIssue {
            data,
            data_bytes,
            context,
            producer,
        });
        Ok(())
    }

    pub(super) fn push_derived(
        &mut self,
        schema: SchemaId,
        version: u32,
        data: Value,
        data_bytes: Vec<u8>,
        root: EvaluationRoot,
        producer: PassId,
    ) -> Result<(), EvaluationStorageError> {
        let table = self
            .derived_tables
            .entry(schema.clone())
            .or_insert_with(|| PendingDerivedTable {
                version,
                rows: Vec::new(),
            });
        if table.version != version {
            return Err(EvaluationStorageError::VersionConflict {
                schema,
                existing: table.version,
                incoming: version,
            });
        }
        table.rows.push(PendingDerived {
            data,
            data_bytes,
            root,
            producer,
        });
        Ok(())
    }

    pub(super) fn merge(&mut self, delta: EvaluationDb) -> Result<(), EvaluationStorageError> {
        for (schema, incoming) in &delta.issue_tables {
            if let Some(existing) = self.issue_tables.get(schema)
                && existing.version != incoming.version
            {
                return Err(EvaluationStorageError::VersionConflict {
                    schema: schema.clone(),
                    existing: existing.version,
                    incoming: incoming.version,
                });
            }
        }
        for (schema, incoming) in &delta.derived_tables {
            if let Some(existing) = self.derived_tables.get(schema)
                && existing.version != incoming.version
            {
                return Err(EvaluationStorageError::VersionConflict {
                    schema: schema.clone(),
                    existing: existing.version,
                    incoming: incoming.version,
                });
            }
        }
        for (schema, mut incoming) in delta.issue_tables {
            self.issue_tables
                .entry(schema)
                .and_modify(|existing| existing.rows.append(&mut incoming.rows))
                .or_insert(incoming);
        }
        for (schema, mut incoming) in delta.derived_tables {
            self.derived_tables
                .entry(schema)
                .and_modify(|existing| existing.rows.append(&mut incoming.rows))
                .or_insert(incoming);
        }
        Ok(())
    }

    pub(super) fn pending_issues<I: IssueSchema>(
        &self,
        registry: &SchemaRegistry,
    ) -> Result<Vec<PendingTypedIssue<I>>, EvaluationStorageError> {
        validate_registered_kind::<I>(registry, TableKind::Issue)?;
        let schema = typed_schema_id::<I>()?;
        let Some(table) = self.issue_tables.get(&schema) else {
            return Ok(Vec::new());
        };
        if table.version != I::VERSION {
            return Err(EvaluationStorageError::VersionConflict {
                schema,
                existing: table.version,
                incoming: I::VERSION,
            });
        }
        let mut rows = table.rows.iter().collect::<Vec<_>>();
        rows.sort_by(|left, right| {
            left.context
                .cmp(&right.context)
                .then_with(|| left.producer.cmp(&right.producer))
                .then_with(|| left.data_bytes.cmp(&right.data_bytes))
        });
        rows.into_iter()
            .map(|row| {
                Ok(PendingTypedIssue {
                    data: decode_row::<I>(&row.data)
                        .map_err(|error| EvaluationStorageError::Codec(error.to_string()))?,
                    context: row.context.clone(),
                    producer: row.producer.clone(),
                })
            })
            .collect()
    }

    pub(super) fn pending_derived<D: DerivedSchema>(
        &self,
        registry: &SchemaRegistry,
    ) -> Result<Vec<PendingTypedDerived<D>>, EvaluationStorageError> {
        validate_registered_kind::<D>(registry, TableKind::Derived)?;
        let schema = typed_schema_id::<D>()?;
        let Some(table) = self.derived_tables.get(&schema) else {
            return Ok(Vec::new());
        };
        if table.version != D::VERSION {
            return Err(EvaluationStorageError::VersionConflict {
                schema,
                existing: table.version,
                incoming: D::VERSION,
            });
        }
        let mut rows = table.rows.iter().collect::<Vec<_>>();
        rows.sort_by(|left, right| {
            left.root
                .cmp(&right.root)
                .then_with(|| left.producer.cmp(&right.producer))
                .then_with(|| left.data_bytes.cmp(&right.data_bytes))
        });
        rows.into_iter()
            .map(|row| {
                Ok(PendingTypedDerived {
                    data: decode_row::<D>(&row.data)
                        .map_err(|error| EvaluationStorageError::Codec(error.to_string()))?,
                    root: row.root.clone(),
                    producer: row.producer.clone(),
                })
            })
            .collect()
    }

    /// Canonicalizes derived and issue row IDs after every rule has completed.
    pub(crate) fn finish(self) -> Result<EvaluationResults, EvaluationStorageError> {
        let mut issue_tables = Vec::with_capacity(self.issue_tables.len());
        let mut issue_index = Vec::new();
        for (schema, mut table) in self.issue_tables {
            table.rows.sort_by(|left, right| {
                left.context
                    .cmp(&right.context)
                    .then_with(|| left.producer.cmp(&right.producer))
                    .then_with(|| left.data_bytes.cmp(&right.data_bytes))
            });
            let mut rows = Vec::with_capacity(table.rows.len());
            for (row, pending) in table.rows.into_iter().enumerate() {
                let row = u32::try_from(row).map_err(|_| EvaluationStorageError::TooManyRows {
                    schema: schema.clone(),
                })?;
                issue_index.push(EvaluatedIssueIndexRow {
                    issue: RowRef {
                        schema: schema.clone(),
                        row,
                    },
                    context: pending.context,
                    producer: pending.producer,
                });
                rows.push(EncodedRow {
                    stable_key: None,
                    data: pending.data,
                });
            }
            issue_tables.push(EncodedTable {
                schema,
                version: table.version,
                kind: TableKind::Issue,
                rows,
            });
        }
        issue_index.sort();

        let mut derived_tables = Vec::with_capacity(self.derived_tables.len());
        let mut derived_index = Vec::new();
        for (schema, mut table) in self.derived_tables {
            table.rows.sort_by(|left, right| {
                left.root
                    .cmp(&right.root)
                    .then_with(|| left.producer.cmp(&right.producer))
                    .then_with(|| left.data_bytes.cmp(&right.data_bytes))
            });
            let mut rows = Vec::with_capacity(table.rows.len());
            for (row, pending) in table.rows.into_iter().enumerate() {
                let row = u32::try_from(row).map_err(|_| EvaluationStorageError::TooManyRows {
                    schema: schema.clone(),
                })?;
                derived_index.push(DerivedIndexRow {
                    derived: RowRef {
                        schema: schema.clone(),
                        row,
                    },
                    root: pending.root,
                    producer: pending.producer,
                });
                rows.push(EncodedRow {
                    stable_key: None,
                    data: pending.data,
                });
            }
            derived_tables.push(EncodedTable {
                schema,
                version: table.version,
                kind: TableKind::Derived,
                rows,
            });
        }
        derived_index.sort();
        Ok(EvaluationResults {
            issue_tables,
            issue_index,
            derived_tables,
            derived_index,
        })
    }
}

#[derive(Clone, Debug)]
pub(super) struct PendingTypedIssue<I: IssueSchema> {
    data: I,
    context: EvaluationIssueContext,
    producer: PassId,
}

impl<I: IssueSchema> PendingTypedIssue<I> {
    pub(super) fn into_parts(self) -> (I, EvaluationIssueContext, PassId) {
        (self.data, self.context, self.producer)
    }
}

#[derive(Clone, Debug)]
pub(super) struct PendingTypedDerived<D: DerivedSchema> {
    data: D,
    root: EvaluationRoot,
    producer: PassId,
}

impl<D: DerivedSchema> PendingTypedDerived<D> {
    pub(super) fn into_parts(self) -> (D, EvaluationRoot, PassId) {
        (self.data, self.root, self.producer)
    }
}

/// Canonical typed intermediate rows and renderer-ready issues for one root.
#[derive(Clone, Debug)]
pub(crate) struct EvaluationResults {
    issue_tables: Vec<EncodedTable>,
    issue_index: Vec<EvaluatedIssueIndexRow>,
    derived_tables: Vec<EncodedTable>,
    derived_index: Vec<DerivedIndexRow>,
}

impl EvaluationResults {
    #[must_use]
    pub(crate) fn issue_tables(&self) -> &[EncodedTable] {
        &self.issue_tables
    }

    #[must_use]
    pub(crate) fn issue_index(&self) -> &[EvaluatedIssueIndexRow] {
        &self.issue_index
    }

    #[must_use]
    pub(crate) fn derived_tables(&self) -> &[EncodedTable] {
        &self.derived_tables
    }

    #[must_use]
    pub(crate) fn derived_index(&self) -> &[DerivedIndexRow] {
        &self.derived_index
    }

    pub(crate) fn issues<I: IssueSchema>(
        &self,
        registry: &SchemaRegistry,
    ) -> Result<Vec<TypedEvaluatedIssue<I>>, EvaluationStorageError> {
        validate_registered_kind::<I>(registry, TableKind::Issue)?;
        let schema = typed_schema_id::<I>()?;
        let Some(table) = self
            .issue_tables
            .iter()
            .find(|table| table.schema == schema)
        else {
            return Ok(Vec::new());
        };
        if table.version != I::VERSION {
            return Err(EvaluationStorageError::VersionConflict {
                schema,
                existing: table.version,
                incoming: I::VERSION,
            });
        }
        let metadata = self
            .issue_index
            .iter()
            .filter(|row| row.issue.schema == schema)
            .map(|row| (row.issue.row, row))
            .collect::<BTreeMap<_, _>>();
        table
            .rows
            .iter()
            .enumerate()
            .map(|(row, encoded)| {
                let row = u32::try_from(row).map_err(|_| EvaluationStorageError::TooManyRows {
                    schema: schema.clone(),
                })?;
                let index = metadata.get(&row).ok_or_else(|| {
                    EvaluationStorageError::MissingIssueMetadata {
                        issue: RowRef {
                            schema: schema.clone(),
                            row,
                        },
                    }
                })?;
                Ok(TypedEvaluatedIssue {
                    reference: index.issue.clone(),
                    data: decode_row::<I>(&encoded.data)
                        .map_err(|error| EvaluationStorageError::Codec(error.to_string()))?,
                    context: index.context.clone(),
                    producer: index.producer.clone(),
                })
            })
            .collect()
    }

    pub(crate) fn derived_rows<D: DerivedSchema>(
        &self,
        registry: &SchemaRegistry,
    ) -> Result<Vec<TypedDerivedRow<D>>, EvaluationStorageError> {
        validate_registered_kind::<D>(registry, TableKind::Derived)?;
        let schema = typed_schema_id::<D>()?;
        let Some(table) = self
            .derived_tables
            .iter()
            .find(|table| table.schema == schema)
        else {
            return Ok(Vec::new());
        };
        if table.version != D::VERSION {
            return Err(EvaluationStorageError::VersionConflict {
                schema,
                existing: table.version,
                incoming: D::VERSION,
            });
        }
        let metadata = self
            .derived_index
            .iter()
            .filter(|row| row.derived.schema == schema)
            .map(|row| (row.derived.row, row))
            .collect::<BTreeMap<_, _>>();
        table
            .rows
            .iter()
            .enumerate()
            .map(|(row, encoded)| {
                let row = u32::try_from(row).map_err(|_| EvaluationStorageError::TooManyRows {
                    schema: schema.clone(),
                })?;
                let index = metadata.get(&row).ok_or_else(|| {
                    EvaluationStorageError::MissingDerivedMetadata {
                        derived: RowRef {
                            schema: schema.clone(),
                            row,
                        },
                    }
                })?;
                Ok(TypedDerivedRow {
                    reference: index.derived.clone(),
                    data: decode_row::<D>(&encoded.data)
                        .map_err(|error| EvaluationStorageError::Codec(error.to_string()))?,
                    root: index.root.clone(),
                    producer: index.producer.clone(),
                })
            })
            .collect()
    }
}

/// Failure at the typed root-specific evaluation storage boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum EvaluationStorageError {
    InvalidSchema {
        schema: String,
        reason: String,
    },
    Registry {
        schema: SchemaId,
        reason: String,
    },
    WrongKind {
        schema: SchemaId,
        expected: TableKind,
        found: TableKind,
    },
    VersionConflict {
        schema: SchemaId,
        existing: u32,
        incoming: u32,
    },
    Codec(String),
    TooManyRows {
        schema: SchemaId,
    },
    MissingIssueMetadata {
        issue: RowRef,
    },
    MissingDerivedMetadata {
        derived: RowRef,
    },
}

impl Display for EvaluationStorageError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSchema { schema, reason } => {
                write!(formatter, "invalid evaluation schema `{schema}`: {reason}")
            }
            Self::Registry { schema, reason } => {
                write!(
                    formatter,
                    "evaluation schema `{schema}` is unavailable: {reason}"
                )
            }
            Self::WrongKind {
                schema,
                expected,
                found,
            } => write!(
                formatter,
                "evaluation schema `{schema}` is {found:?}, expected {expected:?}"
            ),
            Self::VersionConflict {
                schema,
                existing,
                incoming,
            } => write!(
                formatter,
                "evaluation schema `{schema}` has incompatible versions {existing} and {incoming}"
            ),
            Self::Codec(reason) => write!(formatter, "could not encode evaluated row: {reason}"),
            Self::TooManyRows { schema } => {
                write!(
                    formatter,
                    "evaluation table `{schema}` has more than u32::MAX rows"
                )
            }
            Self::MissingIssueMetadata { issue } => write!(
                formatter,
                "evaluated issue `{}`:{} has no context metadata",
                issue.schema, issue.row
            ),
            Self::MissingDerivedMetadata { derived } => write!(
                formatter,
                "derived evaluation row `{}`:{} has no root metadata",
                derived.schema, derived.row
            ),
        }
    }
}

impl Error for EvaluationStorageError {}

fn typed_schema_id<S: RowSchema>() -> Result<SchemaId, EvaluationStorageError> {
    SchemaId::new(S::ID).map_err(|error| EvaluationStorageError::InvalidSchema {
        schema: S::ID.to_owned(),
        reason: error.to_string(),
    })
}

pub(super) fn validate_registered_kind<S: RowSchema>(
    registry: &SchemaRegistry,
    expected: TableKind,
) -> Result<(), EvaluationStorageError> {
    let schema = typed_schema_id::<S>()?;
    let descriptor =
        registry
            .descriptor_for::<S>()
            .map_err(|error| EvaluationStorageError::Registry {
                schema: schema.clone(),
                reason: error.to_string(),
            })?;
    if descriptor.kind() != expected {
        return Err(EvaluationStorageError::WrongKind {
            schema,
            expected,
            found: descriptor.kind(),
        });
    }
    Ok(())
}
