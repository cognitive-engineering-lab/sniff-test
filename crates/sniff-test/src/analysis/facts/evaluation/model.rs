//! Root and provenance records shared by evaluation rules and results.

use serde::{Deserialize, Deserializer, Serialize};

use super::super::composition::{CompositionRelationRef, WorkspaceRelationRef};
use super::super::schema::{DerivedSchema, RowSchema, SchemaId, StableIdError};
use super::super::workspace::{ScopedEntityRef, ScopedRelationRef, ScopedRowRef};

/// Stable analysis-domain identity used to select root-specific policy.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct DomainId(SchemaId);

impl DomainId {
    pub(crate) fn new(value: impl Into<String>) -> Result<Self, StableIdError> {
        SchemaId::new(value).map(Self)
    }

    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// One selected report root and evaluation domain.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct EvaluationRoot {
    pub(crate) domain: DomainId,
    pub(crate) entity: ScopedEntityRef,
}

impl EvaluationRoot {
    #[must_use]
    pub(crate) const fn new(domain: DomainId, entity: ScopedEntityRef) -> Self {
        Self { domain, entity }
    }
}

/// A selected explanatory path through persisted relation rows.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct RelationTrace {
    root: ScopedEntityRef,
    target: ScopedEntityRef,
    relations: Vec<WorkspaceRelationRef>,
}

impl RelationTrace {
    #[must_use]
    pub(crate) const fn new(
        root: ScopedEntityRef,
        target: ScopedEntityRef,
        relations: Vec<WorkspaceRelationRef>,
    ) -> Self {
        Self {
            root,
            target,
            relations,
        }
    }

    #[must_use]
    pub(crate) const fn root(&self) -> &ScopedEntityRef {
        &self.root
    }

    #[must_use]
    pub(crate) const fn target(&self) -> &ScopedEntityRef {
        &self.target
    }

    #[must_use]
    pub(crate) fn relations(&self) -> &[WorkspaceRelationRef] {
        &self.relations
    }
}

/// Decodes a relation trace with strict nested-field validation for new schemas.
///
/// The shared legacy trace remains backward compatible; callers opt into this
/// decoder at their own v1 field boundary.
pub(crate) fn deserialize_strict_relation_trace<'de, D>(
    deserializer: D,
) -> Result<RelationTrace, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(rename_all = "kebab-case", deny_unknown_fields)]
    struct StrictRelationTrace {
        root: ScopedEntityRef,
        target: ScopedEntityRef,
        relations: Vec<StrictWorkspaceRelationRef>,
    }

    #[derive(Deserialize)]
    #[serde(
        tag = "storage",
        content = "reference",
        rename_all = "kebab-case",
        deny_unknown_fields
    )]
    enum StrictWorkspaceRelationRef {
        Artifact(ScopedRelationRef),
        Composition(CompositionRelationRef),
    }

    let strict = StrictRelationTrace::deserialize(deserializer)?;
    let relations = strict
        .relations
        .into_iter()
        .map(|reference| match reference {
            StrictWorkspaceRelationRef::Artifact(reference) => {
                WorkspaceRelationRef::Artifact(reference)
            }
            StrictWorkspaceRelationRef::Composition(reference) => {
                WorkspaceRelationRef::Composition(reference)
            }
        })
        .collect();
    Ok(RelationTrace::new(strict.root, strict.target, relations))
}

/// Root/context metadata stored beside one evaluated issue.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct EvaluationIssueContext {
    pub(crate) root: EvaluationRoot,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) source: Option<ScopedRowRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) endpoint: Option<ScopedEntityRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) trace: Option<RelationTrace>,
}

impl EvaluationIssueContext {
    #[must_use]
    pub(crate) const fn new(root: EvaluationRoot) -> Self {
        Self {
            root,
            source: None,
            endpoint: None,
            trace: None,
        }
    }

    #[must_use]
    pub(crate) fn with_source(mut self, source: ScopedRowRef) -> Self {
        self.source = Some(source);
        self
    }

    #[must_use]
    pub(crate) fn with_endpoint(mut self, endpoint: ScopedEntityRef) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    #[must_use]
    pub(crate) fn with_trace(mut self, trace: RelationTrace) -> Self {
        self.trace = Some(trace);
        self
    }
}

/// A root-specific requirement instance caused by an arbitrary artifact row.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct ObligationRecord {
    domain: DomainId,
    source: ScopedRowRef,
    endpoint: ScopedEntityRef,
    requirements: Vec<ScopedRowRef>,
    trace_target: ScopedEntityRef,
    trace: RelationTrace,
    witness_order: u64,
}

impl RowSchema for ObligationRecord {
    const ID: &'static str = "core.evaluation.obligation";
    const VERSION: u32 = 2;
}

impl DerivedSchema for ObligationRecord {}

impl ObligationRecord {
    #[must_use]
    pub(crate) fn new(
        domain: DomainId,
        source: ScopedRowRef,
        endpoint: ScopedEntityRef,
        mut requirements: Vec<ScopedRowRef>,
        trace_target: ScopedEntityRef,
        trace: RelationTrace,
    ) -> Self {
        requirements.sort();
        requirements.dedup();
        Self {
            domain,
            source,
            endpoint,
            requirements,
            trace_target,
            trace,
            witness_order: 0,
        }
    }

    /// Retains the deterministic order chosen by the root traversal.
    ///
    /// This is semantic witness order, not pass execution or insertion order.
    /// Renderers may use it to preserve source-order diagnostics when several
    /// paths reach the same obligation endpoint.
    #[must_use]
    pub(crate) const fn with_witness_order(mut self, witness_order: u64) -> Self {
        self.witness_order = witness_order;
        self
    }

    #[must_use]
    pub(crate) const fn domain(&self) -> &DomainId {
        &self.domain
    }

    #[must_use]
    pub(crate) const fn source(&self) -> &ScopedRowRef {
        &self.source
    }

    #[must_use]
    pub(crate) const fn endpoint(&self) -> &ScopedEntityRef {
        &self.endpoint
    }

    #[must_use]
    pub(crate) fn requirements(&self) -> &[ScopedRowRef] {
        &self.requirements
    }

    #[must_use]
    pub(crate) const fn trace_target(&self) -> &ScopedEntityRef {
        &self.trace_target
    }

    #[must_use]
    pub(crate) const fn trace(&self) -> &RelationTrace {
        &self.trace
    }

    #[must_use]
    pub(crate) const fn witness_order(&self) -> u64 {
        self.witness_order
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;
    use serde_json::json;

    use super::{RelationTrace, deserialize_strict_relation_trace};
    use crate::analysis::facts::composition::{CompositionRelationRef, WorkspaceRelationRef};
    use crate::analysis::facts::encoded::EntityRef;
    use crate::analysis::facts::schema::SchemaId;
    use crate::analysis::facts::workspace::{ArtifactScopeId, ScopedEntityRef};

    #[derive(Deserialize)]
    struct StrictTraceField {
        #[serde(deserialize_with = "deserialize_strict_relation_trace")]
        trace: RelationTrace,
    }

    fn entity(row: u32) -> ScopedEntityRef {
        ScopedEntityRef::new(
            ArtifactScopeId::for_in_memory(1, 0),
            EntityRef {
                schema: SchemaId::new("sample.trace-node").unwrap(),
                row,
            },
        )
    }

    #[test]
    fn strict_trace_decoder_rejects_unknown_trace_and_relation_envelope_fields() {
        let trace = RelationTrace::new(
            entity(0),
            entity(1),
            vec![WorkspaceRelationRef::Composition(CompositionRelationRef {
                schema: SchemaId::new("sample.trace-edge").unwrap(),
                row: 0,
            })],
        );
        let mut value = json!({ "trace": trace });
        value["trace"]["unexpected"] = json!(true);
        assert!(serde_json::from_value::<StrictTraceField>(value).is_err());

        let mut value = json!({ "trace": trace });
        value["trace"]["relations"][0]["unexpected"] = json!(true);
        assert!(serde_json::from_value::<StrictTraceField>(value).is_err());

        let decoded =
            serde_json::from_value::<StrictTraceField>(json!({ "trace": trace })).unwrap();
        assert_eq!(decoded.trace.target(), &entity(1));
    }
}
