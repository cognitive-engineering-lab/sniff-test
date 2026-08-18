//! Open, deterministic persistence boundary for artifact facts.
//!
//! Domain-specific row values are erased to JSON only in this module. Typed
//! collection and evaluation code accesses them through registered schemas.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::schema::{PassId, SchemaId};

/// Version of the open fact-database container, independent of table schemas.
pub(crate) const FACT_IR_FORMAT_VERSION: u32 = 1;

/// Resource limits applied before generic fact-database shape validation.
///
/// A cache reader may supply tighter limits, while ordinary construction and
/// typed views use the conservative defaults through [`ArtifactFactIr::validate_shape`].
/// `json_value_bytes` and `json_bytes` bound erased values after
/// deserialization; the enclosing cache file must be bounded separately before
/// it is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ArtifactFactIrLimits {
    pub(crate) tables: usize,
    pub(crate) rows_per_table: usize,
    pub(crate) total_rows: usize,
    pub(crate) index_rows: usize,
    pub(crate) requirements_per_fact: usize,
    pub(crate) total_requirement_refs: usize,
    pub(crate) string_bytes: usize,
    pub(crate) json_depth: usize,
    pub(crate) json_nodes_per_value: usize,
    pub(crate) json_value_bytes: usize,
    pub(crate) json_bytes: usize,
}

impl ArtifactFactIrLimits {
    pub(crate) const DEFAULT: Self = Self {
        tables: 4_096,
        rows_per_table: 1_000_000,
        total_rows: 4_000_000,
        index_rows: 4_000_000,
        requirements_per_fact: 4_096,
        total_requirement_refs: 4_000_000,
        string_bytes: 1 << 20,
        json_depth: 64,
        json_nodes_per_value: 65_536,
        json_value_bytes: 4 << 20,
        json_bytes: 256 << 20,
    };
}

impl Default for ArtifactFactIrLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Infrastructure role of an encoded table.
///
/// This enum says how the core validates rows. It does not identify an
/// analysis domain or the meaning of any row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum TableKind {
    Entity,
    Fact,
    Relation,
    Requirement,
    Derived,
    Issue,
}

/// Erased reference to an arbitrary table row.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct RowRef {
    pub(crate) schema: SchemaId,
    pub(crate) row: u32,
}

/// Erased reference to an entity row.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct EntityRef {
    pub(crate) schema: SchemaId,
    pub(crate) row: u32,
}

impl From<EntityRef> for RowRef {
    fn from(entity: EntityRef) -> Self {
        Self {
            schema: entity.schema,
            row: entity.row,
        }
    }
}

/// One canonical row at the persistence boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct EncodedRow {
    /// Stable semantic identity for entity rows; absent for all other rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) stable_key: Option<Value>,
    pub(crate) data: Value,
}

/// One independently versioned typed table in erased form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct EncodedTable {
    pub(crate) schema: SchemaId,
    pub(crate) version: u32,
    pub(crate) kind: TableKind,
    pub(crate) rows: Vec<EncodedRow>,
}

/// Common provenance stored beside a fact without constraining its schema.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct FactIndexRow {
    pub(crate) fact: RowRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) owner: Option<EntityRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) anchor: Option<EntityRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) provenance_root: Option<EntityRef>,
    /// Typed requirement rows referenced by this fact, in canonical order.
    pub(crate) requirements: Vec<RowRef>,
    pub(crate) producer: PassId,
}

/// Generic provenance relation available to adjacency and path selection.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct RelationIndexRow {
    pub(crate) relation: RowRef,
    pub(crate) from: EntityRef,
    pub(crate) to: EntityRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) source: Option<EntityRef>,
}

/// Policy-neutral open fact database extracted from one artifact generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct ArtifactFactIr {
    pub(crate) format_version: u32,
    pub(crate) tables: Vec<EncodedTable>,
    pub(crate) fact_index: Vec<FactIndexRow>,
    pub(crate) relation_index: Vec<RelationIndexRow>,
}

impl ArtifactFactIr {
    /// Checks generic container integrity without requiring domain schemas.
    pub(crate) fn validate_shape(&self) -> Result<(), ArtifactFactIrError> {
        self.validate_shape_with_limits(&ArtifactFactIrLimits::DEFAULT)
    }

    /// Checks generic container integrity under explicit resource limits.
    pub(crate) fn validate_shape_with_limits(
        &self,
        limits: &ArtifactFactIrLimits,
    ) -> Result<(), ArtifactFactIrError> {
        if self.format_version != FACT_IR_FORMAT_VERSION {
            return Err(ArtifactFactIrError::new(format!(
                "fact database declares format {}, expected {}",
                self.format_version, FACT_IR_FORMAT_VERSION
            )));
        }
        validate_resource_limits(self, limits)?;

        let mut tables = BTreeMap::new();
        for table in &self.tables {
            validate_artifact_table_kind(table)?;
            if table.version == 0 {
                return Err(ArtifactFactIrError::new(format!(
                    "table `{}` declares schema version zero",
                    table.schema
                )));
            }
            if tables.insert(&table.schema, table).is_some() {
                return Err(ArtifactFactIrError::new(format!(
                    "fact database contains duplicate table `{}`",
                    table.schema
                )));
            }
            validate_row_shape(table)?;
        }
        if !strictly_ordered(self.tables.iter().map(|table| &table.schema)) {
            return Err(ArtifactFactIrError::new(
                "fact database tables are not in canonical schema order",
            ));
        }

        if !strictly_ordered_values(self.fact_index.iter()) {
            return Err(ArtifactFactIrError::new(
                "generic fact index is not in canonical row-reference order",
            ));
        }
        let mut indexed_facts = BTreeSet::new();
        for fact in &self.fact_index {
            validate_row_ref(&tables, &fact.fact, TableKind::Fact, "fact index row")?;
            for (label, entity) in [
                ("fact owner", fact.owner.as_ref()),
                ("fact source anchor", fact.anchor.as_ref()),
                ("fact provenance root", fact.provenance_root.as_ref()),
            ] {
                if let Some(entity) = entity {
                    validate_entity_ref(&tables, entity, label)?;
                }
            }
            if !strictly_ordered_values(fact.requirements.iter()) {
                return Err(ArtifactFactIrError::new(format!(
                    "fact row `{}`:{} has noncanonical or duplicate requirement references",
                    fact.fact.schema, fact.fact.row
                )));
            }
            for requirement in &fact.requirements {
                validate_row_ref(
                    &tables,
                    requirement,
                    TableKind::Requirement,
                    "fact requirement",
                )?;
            }
            if !indexed_facts.insert(fact.fact.clone()) {
                return Err(ArtifactFactIrError::new(format!(
                    "fact row `{}`:{} has duplicate metadata",
                    fact.fact.schema, fact.fact.row
                )));
            }
        }
        validate_index_coverage(&tables, TableKind::Fact, &indexed_facts, "fact")?;
        validate_fact_row_order(&tables, &self.fact_index)?;

        if !strictly_ordered_values(self.relation_index.iter()) {
            return Err(ArtifactFactIrError::new(
                "generic relation index is not in canonical row-reference order",
            ));
        }
        let mut indexed_relations = BTreeSet::new();
        for relation in &self.relation_index {
            validate_row_ref(
                &tables,
                &relation.relation,
                TableKind::Relation,
                "relation index row",
            )?;
            validate_entity_ref(&tables, &relation.from, "relation `from` endpoint")?;
            validate_entity_ref(&tables, &relation.to, "relation `to` endpoint")?;
            if let Some(source) = &relation.source {
                validate_entity_ref(&tables, source, "relation source anchor")?;
            }
            if !indexed_relations.insert(relation.relation.clone()) {
                return Err(ArtifactFactIrError::new(format!(
                    "relation row `{}`:{} has duplicate endpoints",
                    relation.relation.schema, relation.relation.row
                )));
            }
        }
        validate_index_coverage(&tables, TableKind::Relation, &indexed_relations, "relation")?;
        validate_relation_row_order(&tables, &self.relation_index)?;

        Ok(())
    }
}

fn validate_resource_limits(
    artifact: &ArtifactFactIr,
    limits: &ArtifactFactIrLimits,
) -> Result<(), ArtifactFactIrError> {
    if artifact.tables.len() > limits.tables {
        return Err(resource_limit_error(format_args!(
            "fact database contains {} tables, maximum is {}",
            artifact.tables.len(),
            limits.tables
        )));
    }

    let mut total_rows = 0usize;
    for table in &artifact.tables {
        if table.rows.len() > limits.rows_per_table {
            return Err(resource_limit_error(format_args!(
                "table `{}` contains {} rows, maximum is {}",
                table.schema,
                table.rows.len(),
                limits.rows_per_table
            )));
        }
        total_rows = total_rows
            .checked_add(table.rows.len())
            .filter(|total| *total <= limits.total_rows)
            .ok_or_else(|| {
                resource_limit_error(format_args!(
                    "fact database contains more than {} total rows",
                    limits.total_rows
                ))
            })?;
    }

    if artifact
        .fact_index
        .len()
        .checked_add(artifact.relation_index.len())
        .is_none_or(|total| total > limits.index_rows)
    {
        return Err(resource_limit_error(format_args!(
            "fact database contains more than {} generic index rows",
            limits.index_rows
        )));
    }

    let mut total_requirement_refs = 0usize;
    for fact in &artifact.fact_index {
        if fact.requirements.len() > limits.requirements_per_fact {
            return Err(resource_limit_error(format_args!(
                "fact row `{}`:{} contains {} requirement references, maximum is {}",
                fact.fact.schema,
                fact.fact.row,
                fact.requirements.len(),
                limits.requirements_per_fact
            )));
        }
        total_requirement_refs = total_requirement_refs
            .checked_add(fact.requirements.len())
            .filter(|total| *total <= limits.total_requirement_refs)
            .ok_or_else(|| {
                resource_limit_error(format_args!(
                    "total requirement-reference count exceeds maximum of {}",
                    limits.total_requirement_refs
                ))
            })?;
    }

    validate_persisted_strings_and_json(artifact, limits)
}

fn validate_persisted_strings_and_json(
    artifact: &ArtifactFactIr,
    limits: &ArtifactFactIrLimits,
) -> Result<(), ArtifactFactIrError> {
    let mut json_bytes = 0usize;
    for table in &artifact.tables {
        validate_string(table.schema.as_str(), "table schema ID", limits)?;
        for (row, encoded) in table.rows.iter().enumerate() {
            if let Some(stable_key) = &encoded.stable_key {
                add_json_bytes(
                    &mut json_bytes,
                    validate_json_value(stable_key, &table.schema, row, "stable key", limits)?,
                    limits,
                )?;
            }
            add_json_bytes(
                &mut json_bytes,
                validate_json_value(&encoded.data, &table.schema, row, "data", limits)?,
                limits,
            )?;
        }
    }

    for fact in &artifact.fact_index {
        validate_row_ref_string(&fact.fact, "fact index row", limits)?;
        for (label, entity) in [
            ("fact owner", fact.owner.as_ref()),
            ("fact source anchor", fact.anchor.as_ref()),
            ("fact provenance root", fact.provenance_root.as_ref()),
        ] {
            if let Some(entity) = entity {
                validate_string(entity.schema.as_str(), label, limits)?;
            }
        }
        for requirement in &fact.requirements {
            validate_row_ref_string(requirement, "fact requirement", limits)?;
        }
        validate_string(fact.producer.as_str(), "fact producer pass ID", limits)?;
    }

    for relation in &artifact.relation_index {
        validate_row_ref_string(&relation.relation, "relation index row", limits)?;
        validate_string(
            relation.from.schema.as_str(),
            "relation `from` endpoint",
            limits,
        )?;
        validate_string(
            relation.to.schema.as_str(),
            "relation `to` endpoint",
            limits,
        )?;
        if let Some(source) = &relation.source {
            validate_string(source.schema.as_str(), "relation source anchor", limits)?;
        }
    }

    Ok(())
}

fn validate_row_ref_string(
    reference: &RowRef,
    label: &str,
    limits: &ArtifactFactIrLimits,
) -> Result<(), ArtifactFactIrError> {
    validate_string(reference.schema.as_str(), label, limits)
}

fn validate_string(
    value: &str,
    label: &str,
    limits: &ArtifactFactIrLimits,
) -> Result<(), ArtifactFactIrError> {
    if value.len() > limits.string_bytes {
        return Err(resource_limit_error(format_args!(
            "{label} contains a string of {} bytes, maximum is {}",
            value.len(),
            limits.string_bytes
        )));
    }
    Ok(())
}

fn validate_json_value(
    value: &Value,
    schema: &SchemaId,
    row: usize,
    field: &str,
    limits: &ArtifactFactIrLimits,
) -> Result<usize, ArtifactFactIrError> {
    if limits.json_nodes_per_value == 0 {
        return Err(json_resource_limit_error(
            schema,
            row,
            field,
            format_args!("contains more than 0 nodes"),
        ));
    }

    let mut node_count = 1usize;
    let mut pending = vec![(value, 0usize)];
    while let Some((value, parent_depth)) = pending.pop() {
        match value {
            Value::String(value) => validate_string(value, "JSON value", limits)?,
            Value::Array(values) => {
                let depth =
                    validate_json_container_depth(schema, row, field, parent_depth, limits)?;
                add_json_nodes(schema, row, field, &mut node_count, values.len(), limits)?;
                pending.extend(values.iter().map(|value| (value, depth)));
            }
            Value::Object(values) => {
                let depth =
                    validate_json_container_depth(schema, row, field, parent_depth, limits)?;
                add_json_nodes(schema, row, field, &mut node_count, values.len(), limits)?;
                for (key, value) in values {
                    validate_string(key, "JSON object key", limits)?;
                    pending.push((value, depth));
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }

    validate_json_encoded_size(value, schema, row, field, limits)
}

fn validate_json_container_depth(
    schema: &SchemaId,
    row: usize,
    field: &str,
    parent_depth: usize,
    limits: &ArtifactFactIrLimits,
) -> Result<usize, ArtifactFactIrError> {
    let depth = parent_depth.checked_add(1).ok_or_else(|| {
        json_resource_limit_error(
            schema,
            row,
            field,
            format_args!("exceeds JSON nesting depth {}", limits.json_depth),
        )
    })?;
    if depth > limits.json_depth {
        return Err(json_resource_limit_error(
            schema,
            row,
            field,
            format_args!(
                "has JSON nesting depth {depth}, maximum is {}",
                limits.json_depth
            ),
        ));
    }
    Ok(depth)
}

fn add_json_nodes(
    schema: &SchemaId,
    row: usize,
    field: &str,
    node_count: &mut usize,
    additional: usize,
    limits: &ArtifactFactIrLimits,
) -> Result<(), ArtifactFactIrError> {
    *node_count = node_count
        .checked_add(additional)
        .filter(|count| *count <= limits.json_nodes_per_value)
        .ok_or_else(|| {
            json_resource_limit_error(
                schema,
                row,
                field,
                format_args!("contains more than {} nodes", limits.json_nodes_per_value),
            )
        })?;
    Ok(())
}

fn validate_json_encoded_size(
    value: &Value,
    schema: &SchemaId,
    row: usize,
    field: &str,
    limits: &ArtifactFactIrLimits,
) -> Result<usize, ArtifactFactIrError> {
    let mut writer = JsonByteLimitWriter::new(limits.json_value_bytes);
    match serde_json::to_writer(&mut writer, value) {
        Ok(()) => Ok(writer.written),
        Err(_) if writer.exceeded => Err(json_resource_limit_error(
            schema,
            row,
            field,
            format_args!(
                "contains more than {} encoded bytes",
                limits.json_value_bytes
            ),
        )),
        Err(error) => Err(ArtifactFactIrError::new(format!(
            "could not measure encoded JSON for table `{schema}` row {row} {field}: {error}"
        ))),
    }
}

fn add_json_bytes(
    total: &mut usize,
    additional: usize,
    limits: &ArtifactFactIrLimits,
) -> Result<(), ArtifactFactIrError> {
    *total = total
        .checked_add(additional)
        .filter(|total| *total <= limits.json_bytes)
        .ok_or_else(|| {
            resource_limit_error(format_args!(
                "erased row values contain more than {} encoded JSON bytes",
                limits.json_bytes
            ))
        })?;
    Ok(())
}

fn json_resource_limit_error(
    schema: &SchemaId,
    row: usize,
    field: &str,
    reason: fmt::Arguments<'_>,
) -> ArtifactFactIrError {
    resource_limit_error(format_args!("table `{schema}` row {row} {field} {reason}"))
}

fn resource_limit_error(reason: fmt::Arguments<'_>) -> ArtifactFactIrError {
    ArtifactFactIrError::new(format!("fact database resource limit exceeded: {reason}"))
}

struct JsonByteLimitWriter {
    written: usize,
    limit: usize,
    exceeded: bool,
}

impl JsonByteLimitWriter {
    const fn new(limit: usize) -> Self {
        Self {
            written: 0,
            limit,
            exceeded: false,
        }
    }
}

impl std::io::Write for JsonByteLimitWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self
            .written
            .checked_add(bytes.len())
            .is_none_or(|written| written > self.limit)
        {
            self.exceeded = true;
            return Err(std::io::Error::other("JSON value exceeds byte limit"));
        }
        self.written += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn validate_artifact_table_kind(table: &EncodedTable) -> Result<(), ArtifactFactIrError> {
    if matches!(table.kind, TableKind::Derived | TableKind::Issue) {
        return Err(ArtifactFactIrError::new(format!(
            "artifact table `{}` uses root-specific {:?} rows",
            table.schema, table.kind
        )));
    }
    Ok(())
}

fn validate_row_shape(table: &EncodedTable) -> Result<(), ArtifactFactIrError> {
    let mut previous_key: Option<Vec<u8>> = None;
    let mut previous_data: Option<Vec<u8>> = None;
    for (row, encoded) in table.rows.iter().enumerate() {
        match (table.kind, &encoded.stable_key) {
            (TableKind::Entity, Some(key)) => {
                let key = canonical_value_bytes(key);
                if let Some(previous) = &previous_key {
                    match previous.cmp(&key) {
                        std::cmp::Ordering::Less => {}
                        std::cmp::Ordering::Equal => {
                            return Err(ArtifactFactIrError::new(format!(
                                "entity table `{}` contains duplicate stable key at row {row}",
                                table.schema
                            )));
                        }
                        std::cmp::Ordering::Greater => {
                            return Err(ArtifactFactIrError::new(format!(
                                "entity table `{}` is not in canonical stable-key order",
                                table.schema
                            )));
                        }
                    }
                }
                previous_key = Some(key);
            }
            (TableKind::Entity, None) => {
                return Err(ArtifactFactIrError::new(format!(
                    "entity table `{}` row {row} has no stable key",
                    table.schema
                )));
            }
            (_, Some(_)) => {
                return Err(ArtifactFactIrError::new(format!(
                    "non-entity table `{}` row {row} declares a stable key",
                    table.schema
                )));
            }
            (_, None) => {}
        }
        if matches!(
            table.kind,
            TableKind::Requirement | TableKind::Derived | TableKind::Issue
        ) {
            let data = canonical_value_bytes(&encoded.data);
            if let Some(previous) = &previous_data {
                if previous > &data {
                    return Err(ArtifactFactIrError::new(format!(
                        "table `{}` is not in canonical row order",
                        table.schema
                    )));
                }
                if table.kind == TableKind::Requirement && previous == &data {
                    return Err(ArtifactFactIrError::new(format!(
                        "table `{}` contains a duplicate requirement row",
                        table.schema
                    )));
                }
            }
            previous_data = Some(data);
        }
    }
    Ok(())
}

fn validate_row_ref(
    tables: &BTreeMap<&SchemaId, &EncodedTable>,
    reference: &RowRef,
    expected_kind: TableKind,
    label: &str,
) -> Result<(), ArtifactFactIrError> {
    let Some(table) = tables.get(&reference.schema) else {
        return Err(ArtifactFactIrError::new(format!(
            "{label} refers to missing table `{}`",
            reference.schema
        )));
    };
    if table.kind != expected_kind {
        return Err(ArtifactFactIrError::new(format!(
            "{label} refers to {:?} table `{}`, expected {:?}",
            table.kind, reference.schema, expected_kind
        )));
    }
    if usize::try_from(reference.row).map_or(true, |row| row >= table.rows.len()) {
        return Err(ArtifactFactIrError::new(format!(
            "{label} refers to missing row `{}`:{}",
            reference.schema, reference.row
        )));
    }
    Ok(())
}

fn validate_entity_ref(
    tables: &BTreeMap<&SchemaId, &EncodedTable>,
    reference: &EntityRef,
    label: &str,
) -> Result<(), ArtifactFactIrError> {
    validate_row_ref(
        tables,
        &RowRef {
            schema: reference.schema.clone(),
            row: reference.row,
        },
        TableKind::Entity,
        label,
    )
}

fn validate_index_coverage(
    tables: &BTreeMap<&SchemaId, &EncodedTable>,
    kind: TableKind,
    indexed: &BTreeSet<RowRef>,
    label: &str,
) -> Result<(), ArtifactFactIrError> {
    for table in tables.values().filter(|table| table.kind == kind) {
        for row in 0..table.rows.len() {
            let row = u32::try_from(row).map_err(|_| {
                ArtifactFactIrError::new(format!("table `{}` has too many rows", table.schema))
            })?;
            let reference = RowRef {
                schema: table.schema.clone(),
                row,
            };
            if !indexed.contains(&reference) {
                return Err(ArtifactFactIrError::new(format!(
                    "{label} row `{}`:{row} has no generic index entry",
                    table.schema
                )));
            }
        }
    }
    Ok(())
}

fn validate_fact_row_order(
    tables: &BTreeMap<&SchemaId, &EncodedTable>,
    index: &[FactIndexRow],
) -> Result<(), ArtifactFactIrError> {
    let metadata = index
        .iter()
        .map(|row| (row.fact.clone(), row))
        .collect::<BTreeMap<_, _>>();
    for table in tables
        .values()
        .filter(|table| table.kind == TableKind::Fact)
    {
        let mut previous = None;
        for (row, encoded) in table.rows.iter().enumerate() {
            let reference = indexed_row_ref(table, row)?;
            let meta = metadata
                .get(&reference)
                .expect("fact index coverage was validated");
            let key = (
                &meta.owner,
                &meta.anchor,
                &meta.provenance_root,
                &meta.requirements,
                &meta.producer,
                canonical_value_bytes(&encoded.data),
            );
            if previous.as_ref().is_some_and(|previous| previous > &key) {
                return Err(ArtifactFactIrError::new(format!(
                    "fact table `{}` is not in canonical row order",
                    table.schema
                )));
            }
            previous = Some(key);
        }
    }
    Ok(())
}

fn validate_relation_row_order(
    tables: &BTreeMap<&SchemaId, &EncodedTable>,
    index: &[RelationIndexRow],
) -> Result<(), ArtifactFactIrError> {
    let metadata = index
        .iter()
        .map(|row| (row.relation.clone(), row))
        .collect::<BTreeMap<_, _>>();
    for table in tables
        .values()
        .filter(|table| table.kind == TableKind::Relation)
    {
        let mut previous = None;
        for (row, encoded) in table.rows.iter().enumerate() {
            let reference = indexed_row_ref(table, row)?;
            let meta = metadata
                .get(&reference)
                .expect("relation index coverage was validated");
            let key = (
                &meta.from,
                &meta.to,
                &meta.source,
                canonical_value_bytes(&encoded.data),
            );
            if previous.as_ref().is_some_and(|previous| previous > &key) {
                return Err(ArtifactFactIrError::new(format!(
                    "relation table `{}` is not in canonical row order",
                    table.schema
                )));
            }
            previous = Some(key);
        }
    }
    Ok(())
}

fn indexed_row_ref(table: &EncodedTable, row: usize) -> Result<RowRef, ArtifactFactIrError> {
    let row = u32::try_from(row).map_err(|_| {
        ArtifactFactIrError::new(format!("table `{}` has too many rows", table.schema))
    })?;
    Ok(RowRef {
        schema: table.schema.clone(),
        row,
    })
}

fn canonical_value_bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("serializing a JSON value cannot fail")
}

fn strictly_ordered<'a>(mut values: impl Iterator<Item = &'a SchemaId>) -> bool {
    let Some(mut previous) = values.next() else {
        return true;
    };
    for value in values {
        if previous >= value {
            return false;
        }
        previous = value;
    }
    true
}

fn strictly_ordered_values<T: Ord>(mut values: impl Iterator<Item = T>) -> bool {
    let Some(mut previous) = values.next() else {
        return true;
    };
    for value in values {
        if previous >= value {
            return false;
        }
        previous = value;
    }
    true
}

/// Structured generic-container validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArtifactFactIrError {
    message: String,
}

impl ArtifactFactIrError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl Display for ArtifactFactIrError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ArtifactFactIrError {}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn table(id: &str, kind: TableKind, rows: Vec<EncodedRow>) -> EncodedTable {
        EncodedTable {
            schema: SchemaId::new(id).expect("valid test schema ID"),
            version: 1,
            kind,
            rows,
        }
    }

    fn entity_row(key: &str) -> EncodedRow {
        EncodedRow {
            stable_key: Some(json!(key)),
            data: json!({ "name": key }),
        }
    }

    fn plain_row(value: &str) -> EncodedRow {
        EncodedRow {
            stable_key: None,
            data: json!({ "value": value }),
        }
    }

    fn artifact(tables: Vec<EncodedTable>) -> ArtifactFactIr {
        ArtifactFactIr {
            format_version: FACT_IR_FORMAT_VERSION,
            tables,
            fact_index: Vec::new(),
            relation_index: Vec::new(),
        }
    }

    fn limits() -> ArtifactFactIrLimits {
        ArtifactFactIrLimits::default()
    }

    #[test]
    fn resource_limits_reject_too_many_tables() {
        let artifact = artifact(vec![
            table("a", TableKind::Requirement, Vec::new()),
            table("b", TableKind::Requirement, Vec::new()),
        ]);
        let limits = ArtifactFactIrLimits {
            tables: 1,
            ..limits()
        };

        let error = artifact
            .validate_shape_with_limits(&limits)
            .expect_err("table count must be bounded");

        assert!(error.to_string().contains("2 tables"));
    }

    #[test]
    fn resource_limits_reject_too_many_rows_in_one_table() {
        let artifact = artifact(vec![table(
            "a",
            TableKind::Requirement,
            vec![plain_row("a"), plain_row("b")],
        )]);
        let limits = ArtifactFactIrLimits {
            rows_per_table: 1,
            ..limits()
        };

        let error = artifact
            .validate_shape_with_limits(&limits)
            .expect_err("per-table row count must be bounded");

        assert!(error.to_string().contains("table `a` contains 2 rows"));
    }

    #[test]
    fn resource_limits_reject_too_many_rows_across_tables() {
        let artifact = artifact(vec![
            table("a", TableKind::Requirement, vec![plain_row("a")]),
            table("b", TableKind::Requirement, vec![plain_row("b")]),
        ]);
        let limits = ArtifactFactIrLimits {
            total_rows: 1,
            ..limits()
        };

        let error = artifact
            .validate_shape_with_limits(&limits)
            .expect_err("total row count must be bounded");

        assert!(error.to_string().contains("more than 1 total rows"));
    }

    #[test]
    fn resource_limits_reject_too_many_generic_index_rows() {
        let schema = SchemaId::new("a").unwrap();
        let producer = PassId::new("p").unwrap();
        let mut artifact = artifact(vec![table(
            "a",
            TableKind::Fact,
            vec![plain_row("a"), plain_row("b")],
        )]);
        artifact.fact_index = (0..2)
            .map(|row| FactIndexRow {
                fact: RowRef {
                    schema: schema.clone(),
                    row,
                },
                owner: None,
                anchor: None,
                provenance_root: None,
                requirements: Vec::new(),
                producer: producer.clone(),
            })
            .collect();
        let limits = ArtifactFactIrLimits {
            index_rows: 1,
            ..limits()
        };

        let error = artifact
            .validate_shape_with_limits(&limits)
            .expect_err("generic index count must be bounded");

        assert!(error.to_string().contains("more than 1 generic index rows"));
    }

    #[test]
    fn resource_limits_reject_too_many_requirements_per_fact() {
        let fact_schema = SchemaId::new("a").unwrap();
        let requirement_schema = SchemaId::new("b").unwrap();
        let mut artifact = artifact(vec![
            table("a", TableKind::Fact, vec![plain_row("fact")]),
            table(
                "b",
                TableKind::Requirement,
                vec![plain_row("a"), plain_row("b")],
            ),
        ]);
        artifact.fact_index.push(FactIndexRow {
            fact: RowRef {
                schema: fact_schema,
                row: 0,
            },
            owner: None,
            anchor: None,
            provenance_root: None,
            requirements: (0..2)
                .map(|row| RowRef {
                    schema: requirement_schema.clone(),
                    row,
                })
                .collect(),
            producer: PassId::new("p").unwrap(),
        });
        let limits = ArtifactFactIrLimits {
            requirements_per_fact: 1,
            ..limits()
        };

        let error = artifact
            .validate_shape_with_limits(&limits)
            .expect_err("requirement fanout must be bounded");

        assert!(error.to_string().contains("2 requirement references"));
    }

    #[test]
    fn resource_limits_reject_too_many_requirement_references_across_facts() {
        let fact_schema = SchemaId::new("a").unwrap();
        let requirement_schema = SchemaId::new("b").unwrap();
        let mut artifact = artifact(vec![
            table("a", TableKind::Fact, vec![plain_row("a"), plain_row("b")]),
            table("b", TableKind::Requirement, vec![plain_row("requirement")]),
        ]);
        artifact.fact_index = (0..2)
            .map(|row| FactIndexRow {
                fact: RowRef {
                    schema: fact_schema.clone(),
                    row,
                },
                owner: None,
                anchor: None,
                provenance_root: None,
                requirements: vec![RowRef {
                    schema: requirement_schema.clone(),
                    row: 0,
                }],
                producer: PassId::new("p").unwrap(),
            })
            .collect();
        let limits = ArtifactFactIrLimits {
            requirements_per_fact: 1,
            total_requirement_refs: 1,
            ..limits()
        };

        let error = artifact
            .validate_shape_with_limits(&limits)
            .expect_err("aggregate requirement references must be bounded");

        assert!(
            error
                .to_string()
                .contains("total requirement-reference count exceeds maximum of 1")
        );
    }

    #[test]
    fn resource_limits_reject_oversized_strings_and_json_values() {
        let artifact = artifact(vec![table(
            "a",
            TableKind::Requirement,
            vec![EncodedRow {
                stable_key: None,
                data: json!("four"),
            }],
        )]);

        let string_error = artifact
            .validate_shape_with_limits(&ArtifactFactIrLimits {
                string_bytes: 3,
                ..limits()
            })
            .expect_err("individual strings must be bounded");
        assert!(string_error.to_string().contains("string of 4 bytes"));

        let value_error = artifact
            .validate_shape_with_limits(&ArtifactFactIrLimits {
                json_value_bytes: 5,
                ..limits()
            })
            .expect_err("encoded JSON values must be bounded");
        assert!(
            value_error
                .to_string()
                .contains("more than 5 encoded bytes")
        );
    }

    #[test]
    fn resource_limits_reject_too_many_encoded_json_bytes_across_rows() {
        let artifact = artifact(vec![table(
            "a",
            TableKind::Requirement,
            vec![
                EncodedRow {
                    stable_key: None,
                    data: json!("a"),
                },
                EncodedRow {
                    stable_key: None,
                    data: json!("b"),
                },
            ],
        )]);

        let error = artifact
            .validate_shape_with_limits(&ArtifactFactIrLimits {
                json_bytes: 5,
                ..limits()
            })
            .expect_err("aggregate encoded JSON size must be bounded");

        assert!(error.to_string().contains("more than 5 encoded JSON bytes"));
    }

    #[test]
    fn resource_limits_reject_deep_or_overly_complex_json() {
        let deep = artifact(vec![table(
            "a",
            TableKind::Requirement,
            vec![EncodedRow {
                stable_key: None,
                data: json!({ "outer": { "inner": true } }),
            }],
        )]);
        let depth_error = deep
            .validate_shape_with_limits(&ArtifactFactIrLimits {
                json_depth: 1,
                ..limits()
            })
            .expect_err("JSON nesting must be bounded");
        assert!(depth_error.to_string().contains("nesting depth 2"));

        let wide = artifact(vec![table(
            "a",
            TableKind::Requirement,
            vec![EncodedRow {
                stable_key: None,
                data: json!([1, 2]),
            }],
        )]);
        let node_error = wide
            .validate_shape_with_limits(&ArtifactFactIrLimits {
                json_nodes_per_value: 2,
                ..limits()
            })
            .expect_err("JSON node count must be bounded");
        assert!(node_error.to_string().contains("more than 2 nodes"));
    }

    #[test]
    fn resource_limits_preserve_normal_unknown_tables() {
        let artifact = artifact(vec![table(
            "future.allocator.requirement",
            TableKind::Requirement,
            vec![plain_row("allocation escaped")],
        )]);
        let limits = ArtifactFactIrLimits {
            tables: 1,
            rows_per_table: 1,
            total_rows: 1,
            index_rows: 0,
            requirements_per_fact: 0,
            total_requirement_refs: 0,
            string_bytes: 64,
            json_depth: 1,
            json_nodes_per_value: 2,
            json_value_bytes: 64,
            json_bytes: 64,
        };

        artifact
            .validate_shape_with_limits(&limits)
            .expect("bounded unknown tables remain valid and opaque");
    }

    #[test]
    fn shape_validation_rejects_duplicate_table_ids() {
        let artifact = artifact(vec![
            table("sample.entity", TableKind::Entity, vec![entity_row("a")]),
            table("sample.entity", TableKind::Entity, vec![entity_row("b")]),
        ]);

        let error = artifact
            .validate_shape()
            .expect_err("duplicate schema IDs must be rejected");

        assert!(error.to_string().contains("sample.entity"));
    }

    #[test]
    fn shape_validation_rejects_dangling_relation_endpoints() {
        let relation_schema = SchemaId::new("sample.relation").unwrap();
        let artifact = ArtifactFactIr {
            format_version: FACT_IR_FORMAT_VERSION,
            tables: vec![
                table("sample.entity", TableKind::Entity, vec![entity_row("a")]),
                EncodedTable {
                    schema: relation_schema.clone(),
                    version: 1,
                    kind: TableKind::Relation,
                    rows: vec![EncodedRow {
                        stable_key: None,
                        data: json!({}),
                    }],
                },
            ],
            fact_index: Vec::new(),
            relation_index: vec![RelationIndexRow {
                relation: RowRef {
                    schema: relation_schema,
                    row: 0,
                },
                from: EntityRef {
                    schema: SchemaId::new("sample.entity").unwrap(),
                    row: 0,
                },
                to: EntityRef {
                    schema: SchemaId::new("sample.entity").unwrap(),
                    row: 1,
                },
                source: None,
            }],
        };

        let error = artifact
            .validate_shape()
            .expect_err("dangling endpoints must be rejected");

        assert!(error.to_string().contains("endpoint"));
    }

    #[test]
    fn shape_validation_requires_canonical_plain_row_order() {
        let artifact = artifact(vec![table(
            "sample.requirement",
            TableKind::Requirement,
            vec![plain_row("z"), plain_row("a")],
        )]);

        let error = artifact
            .validate_shape()
            .expect_err("plain rows must be in canonical encoded order");

        assert!(error.to_string().contains("canonical row order"));
    }

    #[test]
    fn shape_validation_rejects_duplicate_requirement_rows() {
        let artifact = artifact(vec![table(
            "sample.requirement",
            TableKind::Requirement,
            vec![plain_row("same"), plain_row("same")],
        )]);

        let error = artifact
            .validate_shape()
            .expect_err("one symbolic requirement identity must have one row");

        assert!(error.to_string().contains("duplicate requirement"));
    }

    #[test]
    fn shape_validation_requires_canonical_fact_index_order() {
        let schema = SchemaId::new("sample.fact").unwrap();
        let producer = PassId::new("sample.collect").unwrap();
        let mut artifact = artifact(vec![EncodedTable {
            schema: schema.clone(),
            version: 1,
            kind: TableKind::Fact,
            rows: vec![plain_row("a"), plain_row("b")],
        }]);
        artifact.fact_index = [1, 0]
            .into_iter()
            .map(|row| FactIndexRow {
                fact: RowRef {
                    schema: schema.clone(),
                    row,
                },
                owner: None,
                anchor: None,
                provenance_root: None,
                requirements: Vec::new(),
                producer: producer.clone(),
            })
            .collect();

        let error = artifact
            .validate_shape()
            .expect_err("generic fact index must use canonical reference order");

        assert!(error.to_string().contains("fact index"));
    }

    #[test]
    fn unknown_tables_round_trip_opaquely() {
        let artifact = artifact(vec![table(
            "future.allocator.requirement",
            TableKind::Requirement,
            vec![plain_row("allocation escaped")],
        )]);

        let bytes = serde_json::to_vec(&artifact).expect("encode open artifact");
        let decoded: ArtifactFactIr = serde_json::from_slice(&bytes).expect("decode open artifact");

        decoded
            .validate_shape()
            .expect("unknown table shape is valid");
        assert_eq!(decoded, artifact);
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), bytes);
    }

    #[test]
    fn artifact_shape_rejects_root_specific_table_kinds() {
        for kind in [TableKind::Derived, TableKind::Issue] {
            let artifact = artifact(vec![table("future.evaluation.row", kind, Vec::new())]);

            let error = artifact
                .validate_shape()
                .expect_err("root-specific rows must not enter artifact caches");

            assert!(error.to_string().contains("root-specific"));
        }
    }

    #[test]
    fn infrastructure_fields_are_strict_while_unknown_row_data_stays_opaque() {
        let value = json!({
            "format-version": FACT_IR_FORMAT_VERSION,
            "tables": [{
                "schema": "future.allocator.fact",
                "version": 1,
                "kind": "fact",
                "rows": [{
                    "data": { "future-field": { "nested": true } }
                }]
            }],
            "fact-index": [{
                "fact": { "schema": "future.allocator.fact", "row": 0 },
                "requirements": [],
                "producer": "future.collect"
            }],
            "relation-index": [],
            "unexpected-container-field": true
        });

        let error = serde_json::from_value::<ArtifactFactIr>(value)
            .expect_err("unknown infrastructure fields must not be ignored");

        assert!(error.to_string().contains("unexpected-container-field"));
    }

    #[test]
    fn shape_validation_requires_canonical_fact_row_order() {
        let schema = SchemaId::new("sample.fact").unwrap();
        let producer = PassId::new("sample.collect").unwrap();
        let mut artifact = artifact(vec![table(
            "sample.fact",
            TableKind::Fact,
            vec![plain_row("z"), plain_row("a")],
        )]);
        artifact.fact_index = (0..2)
            .map(|row| FactIndexRow {
                fact: RowRef {
                    schema: schema.clone(),
                    row,
                },
                owner: None,
                anchor: None,
                provenance_root: None,
                requirements: Vec::new(),
                producer: producer.clone(),
            })
            .collect();

        let error = artifact
            .validate_shape()
            .expect_err("fact payloads participate in canonical row order");

        assert!(error.to_string().contains("fact table"));
    }

    #[test]
    fn shape_validation_requires_canonical_relation_rows_and_index() {
        let relation_schema = SchemaId::new("sample.relation").unwrap();
        let entity_schema = SchemaId::new("sample.entity").unwrap();
        let relation_ref = |row| RowRef {
            schema: relation_schema.clone(),
            row,
        };
        let endpoint = |row| EntityRef {
            schema: entity_schema.clone(),
            row,
        };
        let tables = vec![
            table(
                "sample.entity",
                TableKind::Entity,
                vec![entity_row("a"), entity_row("b")],
            ),
            table(
                "sample.relation",
                TableKind::Relation,
                vec![plain_row("z"), plain_row("a")],
            ),
        ];
        let canonical_index = vec![
            RelationIndexRow {
                relation: relation_ref(0),
                from: endpoint(0),
                to: endpoint(1),
                source: None,
            },
            RelationIndexRow {
                relation: relation_ref(1),
                from: endpoint(0),
                to: endpoint(1),
                source: None,
            },
        ];
        let artifact = ArtifactFactIr {
            format_version: FACT_IR_FORMAT_VERSION,
            tables: tables.clone(),
            fact_index: Vec::new(),
            relation_index: canonical_index.clone(),
        };

        let row_error = artifact
            .validate_shape()
            .expect_err("relation payloads participate in canonical row order");
        assert!(row_error.to_string().contains("relation table"));

        let mut reversed_index = canonical_index;
        reversed_index.reverse();
        let artifact = ArtifactFactIr {
            format_version: FACT_IR_FORMAT_VERSION,
            tables,
            fact_index: Vec::new(),
            relation_index: reversed_index,
        };
        let index_error = artifact
            .validate_shape()
            .expect_err("relation index order must be canonical");
        assert!(index_error.to_string().contains("relation index"));
    }
}
