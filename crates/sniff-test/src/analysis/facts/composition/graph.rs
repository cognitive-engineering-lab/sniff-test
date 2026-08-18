//! Deterministic mixed persisted/composition provenance graph.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::iter::Peekable;
use std::ops::Range;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::super::encoded::TableKind;
use super::super::evaluation::EvaluationRoot;
use super::super::schema::SchemaId;
use super::super::workspace::{
    ScopedEntityRef, ScopedRelationRef, WorkspaceFactView, WorkspaceIdentity,
};
use super::{CompositionRelationDb, CompositionRelationRef};

/// Infrastructure storage origin of one relation selected for a trace.
///
/// These variants distinguish resolution boundaries, not relation semantics;
/// adding a new analysis relation never changes this enum.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "storage", content = "reference", rename_all = "kebab-case")]
pub(crate) enum WorkspaceRelationRef {
    Artifact(ScopedRelationRef),
    Composition(CompositionRelationRef),
}

impl WorkspaceRelationRef {
    #[must_use]
    pub(crate) fn schema(&self) -> &SchemaId {
        match self {
            Self::Artifact(reference) => &reference.relation().schema,
            Self::Composition(reference) => &reference.schema,
        }
    }
}

/// Generic endpoint metadata for either a persisted or composed relation.
///
/// Every endpoint and optional source retains its exact artifact-generation
/// scope. A record crosses scopes only when it originated in the explicit,
/// root-bound [`CompositionRelationDb`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkspaceRelationRecord {
    pub(crate) relation: WorkspaceRelationRef,
    pub(crate) from: ScopedEntityRef,
    pub(crate) to: ScopedEntityRef,
    pub(crate) source: Option<ScopedEntityRef>,
}

/// Immutable artifact-only provenance index for one exact workspace view.
///
/// Construction scans artifact entity and relation tables once. Root-specific
/// graphs clone only this small `Arc` handle and index their ephemeral
/// composition relations separately.
#[derive(Clone, Debug)]
pub(crate) struct WorkspaceRelationIndex {
    inner: Arc<WorkspaceRelationIndexInner>,
}

#[derive(Debug)]
struct WorkspaceRelationIndexInner {
    workspace: Arc<WorkspaceIdentity>,
    entities: BTreeSet<ScopedEntityRef>,
    relations: Vec<WorkspaceRelationRecord>,
    by_reference: BTreeMap<WorkspaceRelationRef, usize>,
    outgoing: BTreeMap<ScopedEntityRef, Vec<usize>>,
    incoming: BTreeMap<ScopedEntityRef, Vec<usize>>,
}

/// Deterministic mixed provenance graph for one exact evaluation root.
///
/// Persisted artifact relations remain inside their artifact scope. The graph
/// never treats semantic entity-key equivalence as an edge; cross-scope paths
/// exist only when the root-bound composition database contains a relation.
#[derive(Debug)]
pub(crate) struct WorkspaceRelationGraph {
    root: EvaluationRoot,
    artifact: WorkspaceRelationIndex,
    composition: CompositionRelationDb,
    relations: Vec<WorkspaceRelationRecord>,
    by_reference: BTreeMap<WorkspaceRelationRef, usize>,
    outgoing: BTreeMap<ScopedEntityRef, Vec<usize>>,
    incoming: BTreeMap<ScopedEntityRef, Vec<usize>>,
}

/// Authoritative binding of workspace facts and root-specific composition.
///
/// Construction builds the only relation graph accepted by workspace rule
/// execution. Keeping the facts and graph behind one value prevents callers
/// from validating rows against one workspace while following relations built
/// from another.
#[derive(Debug)]
pub(crate) struct WorkspaceEvaluationView<'a> {
    facts: &'a WorkspaceFactView<'a>,
    graph: WorkspaceRelationGraph,
}

impl<'a> WorkspaceEvaluationView<'a> {
    pub(crate) fn open(
        root: &EvaluationRoot,
        facts: &'a WorkspaceFactView<'a>,
        composition: &CompositionRelationDb,
    ) -> Result<Self, WorkspaceRelationError> {
        let graph = WorkspaceRelationGraph::new(root, facts, composition)?;
        Self::from_graph(facts, graph)
    }

    /// Binds a graph that was already used to validate root-specific inputs.
    ///
    /// The opaque workspace brand makes this an O(1) proof that the graph's
    /// artifact index and the rule-visible facts came from the same exact view.
    pub(crate) fn from_graph(
        facts: &'a WorkspaceFactView<'a>,
        graph: WorkspaceRelationGraph,
    ) -> Result<Self, WorkspaceRelationError> {
        if !graph.artifact.belongs_to(facts) {
            return Err(WorkspaceRelationError::WorkspaceMismatch);
        }
        Ok(Self { facts, graph })
    }

    #[must_use]
    pub(crate) const fn root(&self) -> &EvaluationRoot {
        self.graph.root()
    }

    #[must_use]
    pub(crate) const fn facts(&self) -> &WorkspaceFactView<'a> {
        self.facts
    }

    #[must_use]
    pub(crate) const fn composition(&self) -> &CompositionRelationDb {
        self.graph.composition()
    }

    #[must_use]
    pub(crate) const fn graph(&self) -> &WorkspaceRelationGraph {
        &self.graph
    }
}

impl WorkspaceRelationIndex {
    /// Scans and indexes every persisted entity and relation exactly once.
    pub(crate) fn open(workspace: &WorkspaceFactView<'_>) -> Result<Self, WorkspaceRelationError> {
        let (entities, mut relations) = collect_artifact_graph(workspace)?;
        relations.sort_by(workspace_relation_order);
        let (by_reference, outgoing, incoming) = index_workspace_relations(&relations)?;
        Ok(Self {
            inner: Arc::new(WorkspaceRelationIndexInner {
                workspace: workspace.identity(),
                entities,
                relations,
                by_reference,
                outgoing,
                incoming,
            }),
        })
    }

    /// Adds one root's ephemeral relations without rescanning artifact tables.
    pub(crate) fn bind(
        &self,
        root: &EvaluationRoot,
        composition: CompositionRelationDb,
    ) -> Result<WorkspaceRelationGraph, WorkspaceRelationError> {
        if !composition.has_workspace_identity(&self.inner.workspace) {
            return Err(WorkspaceRelationError::WorkspaceMismatch);
        }
        composition
            .validate_root(root)
            .map_err(|_| WorkspaceRelationError::RootMismatch {
                expected: Box::new(composition.root().clone()),
                found: Box::new(root.clone()),
            })?;
        if !self.inner.entities.contains(&root.entity) {
            return Err(WorkspaceRelationError::InvalidWorkspaceReference {
                reason: format!("evaluation root is unavailable: {:?}", root.entity),
            });
        }

        let mut relations = collect_composition_graph(&self.inner.entities, &composition)?;
        relations.sort_by(workspace_relation_order);
        let (by_reference, outgoing, incoming) = index_workspace_relations(&relations)?;
        Ok(WorkspaceRelationGraph {
            root: root.clone(),
            artifact: self.clone(),
            composition,
            relations,
            by_reference,
            outgoing,
            incoming,
        })
    }

    fn belongs_to(&self, workspace: &WorkspaceFactView<'_>) -> bool {
        workspace.has_identity(&self.inner.workspace)
    }
}

impl WorkspaceRelationGraph {
    pub(crate) fn new(
        root: &EvaluationRoot,
        workspace: &WorkspaceFactView<'_>,
        composition: &CompositionRelationDb,
    ) -> Result<Self, WorkspaceRelationError> {
        WorkspaceRelationIndex::open(workspace)?.bind(root, composition.clone())
    }

    #[must_use]
    pub(crate) const fn root(&self) -> &EvaluationRoot {
        &self.root
    }

    #[must_use]
    pub(crate) const fn composition(&self) -> &CompositionRelationDb {
        &self.composition
    }

    pub(in crate::analysis::facts) fn has_workspace_identity(
        &self,
        identity: &Arc<WorkspaceIdentity>,
    ) -> bool {
        Arc::ptr_eq(&self.artifact.inner.workspace, identity)
    }

    pub(crate) fn relations(&self) -> impl ExactSizeIterator<Item = &WorkspaceRelationRecord> {
        MergedRelations::all(&self.artifact.inner.relations, &self.relations)
    }

    pub(crate) fn outgoing<'a>(
        &'a self,
        entity: &ScopedEntityRef,
    ) -> impl ExactSizeIterator<Item = &'a WorkspaceRelationRecord> {
        MergedRelations::selected(
            &self.artifact.inner.relations,
            self.artifact.inner.outgoing.get(entity).map(Vec::as_slice),
            &self.relations,
            self.outgoing.get(entity).map(Vec::as_slice),
        )
    }

    pub(crate) fn incoming<'a>(
        &'a self,
        entity: &ScopedEntityRef,
    ) -> impl ExactSizeIterator<Item = &'a WorkspaceRelationRecord> {
        MergedRelations::selected(
            &self.artifact.inner.relations,
            self.artifact.inner.incoming.get(entity).map(Vec::as_slice),
            &self.relations,
            self.incoming.get(entity).map(Vec::as_slice),
        )
    }

    #[must_use]
    pub(crate) fn shortest_path(
        &self,
        from: &ScopedEntityRef,
        to: &ScopedEntityRef,
    ) -> Option<Vec<WorkspaceRelationRef>> {
        if !self.artifact.inner.entities.contains(from)
            || !self.artifact.inner.entities.contains(to)
        {
            return None;
        }
        if from == to {
            return Some(Vec::new());
        }

        let mut queue = VecDeque::from([from.clone()]);
        let mut visited = BTreeSet::from([from.clone()]);
        let mut predecessor =
            BTreeMap::<ScopedEntityRef, (ScopedEntityRef, WorkspaceRelationRef)>::new();
        while let Some(current) = queue.pop_front() {
            for relation in self.outgoing(&current) {
                if !visited.insert(relation.to.clone()) {
                    continue;
                }
                predecessor.insert(
                    relation.to.clone(),
                    (current.clone(), relation.relation.clone()),
                );
                if &relation.to == to {
                    return reconstruct_workspace_path(from, to, &predecessor);
                }
                queue.push_back(relation.to.clone());
            }
        }
        None
    }

    pub(crate) fn validate_path(
        &self,
        from: &ScopedEntityRef,
        to: &ScopedEntityRef,
        path: &[WorkspaceRelationRef],
    ) -> Result<Vec<WorkspaceRelationRecord>, WorkspaceRelationError> {
        for entity in [from, to] {
            if !self.artifact.inner.entities.contains(entity) {
                return Err(WorkspaceRelationError::UnknownEntity {
                    entity: Box::new(entity.clone()),
                });
            }
        }

        let mut current = from.clone();
        let mut resolved = Vec::with_capacity(path.len());
        for (position, reference) in path.iter().enumerate() {
            let relation = self.relation(reference).ok_or_else(|| {
                WorkspaceRelationError::MissingRelation {
                    relation: reference.clone(),
                }
            })?;
            if relation.from != current {
                return Err(WorkspaceRelationError::PathDiscontinuity {
                    position,
                    expected: Box::new(current),
                    found: Box::new(relation.from.clone()),
                });
            }
            current = relation.to.clone();
            resolved.push(relation.clone());
        }
        if &current != to {
            return Err(WorkspaceRelationError::PathTargetMismatch {
                expected: Box::new(to.clone()),
                found: Box::new(current),
            });
        }
        Ok(resolved)
    }

    fn relation(&self, reference: &WorkspaceRelationRef) -> Option<&WorkspaceRelationRecord> {
        match reference {
            WorkspaceRelationRef::Artifact(_) => self
                .artifact
                .inner
                .by_reference
                .get(reference)
                .map(|index| &self.artifact.inner.relations[*index]),
            WorkspaceRelationRef::Composition(_) => self
                .by_reference
                .get(reference)
                .map(|index| &self.relations[*index]),
        }
    }
}

fn collect_artifact_graph(
    workspace: &WorkspaceFactView<'_>,
) -> Result<(BTreeSet<ScopedEntityRef>, Vec<WorkspaceRelationRecord>), WorkspaceRelationError> {
    let mut entities = BTreeSet::new();
    let mut relations = Vec::new();
    for scope in workspace.scopes() {
        let view = workspace.artifact(scope).map_err(|error| {
            WorkspaceRelationError::InvalidWorkspaceReference {
                reason: error.to_string(),
            }
        })?;
        for table in &view.artifact().tables {
            if table.kind != TableKind::Entity {
                continue;
            }
            for row in 0..table.rows.len() {
                let row = u32::try_from(row).map_err(|_| {
                    WorkspaceRelationError::InvalidWorkspaceReference {
                        reason: format!(
                            "entity table `{}` exceeds workspace row IDs",
                            table.schema
                        ),
                    }
                })?;
                entities.insert(ScopedEntityRef::new(
                    scope.clone(),
                    super::super::encoded::EntityRef {
                        schema: table.schema.clone(),
                        row,
                    },
                ));
            }
        }
        relations.extend(view.artifact().relation_index.iter().map(|relation| {
            WorkspaceRelationRecord {
                relation: WorkspaceRelationRef::Artifact(ScopedRelationRef::new(
                    scope.clone(),
                    relation.relation.clone(),
                )),
                from: ScopedEntityRef::new(scope.clone(), relation.from.clone()),
                to: ScopedEntityRef::new(scope.clone(), relation.to.clone()),
                source: relation
                    .source
                    .clone()
                    .map(|source| ScopedEntityRef::new(scope.clone(), source)),
            }
        }));
    }
    Ok((entities, relations))
}

fn collect_composition_graph(
    entities: &BTreeSet<ScopedEntityRef>,
    composition: &CompositionRelationDb,
) -> Result<Vec<WorkspaceRelationRecord>, WorkspaceRelationError> {
    let mut relations = Vec::with_capacity(composition.relations().len());
    for relation in composition.relations() {
        for (label, endpoint) in [("from", &relation.from), ("to", &relation.to)] {
            if !entities.contains(endpoint) {
                return Err(WorkspaceRelationError::InvalidWorkspaceReference {
                    reason: format!(
                        "composition relation {:?} {label} endpoint is unavailable: {endpoint:?}",
                        relation.relation
                    ),
                });
            }
        }
        if let Some(source) = &relation.source
            && !entities.contains(source)
        {
            return Err(WorkspaceRelationError::InvalidWorkspaceReference {
                reason: format!(
                    "composition relation {:?} source is unavailable: {source:?}",
                    relation.relation
                ),
            });
        }
        relations.push(WorkspaceRelationRecord {
            relation: WorkspaceRelationRef::Composition(relation.relation.clone()),
            from: relation.from.clone(),
            to: relation.to.clone(),
            source: relation.source.clone(),
        });
    }
    Ok(relations)
}

#[derive(Clone)]
enum RelationPositions<'a> {
    All(Range<usize>),
    Selected(std::slice::Iter<'a, usize>),
}

impl Iterator for RelationPositions<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::All(positions) => positions.next(),
            Self::Selected(positions) => positions.next().copied(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.len();
        (len, Some(len))
    }
}

impl ExactSizeIterator for RelationPositions<'_> {
    fn len(&self) -> usize {
        match self {
            Self::All(positions) => positions.len(),
            Self::Selected(positions) => positions.len(),
        }
    }
}

#[derive(Clone)]
struct RelationIter<'a> {
    records: &'a [WorkspaceRelationRecord],
    positions: RelationPositions<'a>,
}

impl<'a> RelationIter<'a> {
    fn all(records: &'a [WorkspaceRelationRecord]) -> Self {
        Self {
            records,
            positions: RelationPositions::All(0..records.len()),
        }
    }

    fn selected(records: &'a [WorkspaceRelationRecord], positions: Option<&'a [usize]>) -> Self {
        Self {
            records,
            positions: RelationPositions::Selected(positions.unwrap_or_default().iter()),
        }
    }
}

impl<'a> Iterator for RelationIter<'a> {
    type Item = &'a WorkspaceRelationRecord;

    fn next(&mut self) -> Option<Self::Item> {
        self.positions.next().map(|index| &self.records[index])
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.len();
        (len, Some(len))
    }
}

impl ExactSizeIterator for RelationIter<'_> {
    fn len(&self) -> usize {
        self.positions.len()
    }
}

/// Stable merge of independently sorted artifact and composition records.
struct MergedRelations<'a> {
    artifact: Peekable<RelationIter<'a>>,
    composition: Peekable<RelationIter<'a>>,
}

impl<'a> MergedRelations<'a> {
    fn all(
        artifact: &'a [WorkspaceRelationRecord],
        composition: &'a [WorkspaceRelationRecord],
    ) -> Self {
        Self {
            artifact: RelationIter::all(artifact).peekable(),
            composition: RelationIter::all(composition).peekable(),
        }
    }

    fn selected(
        artifact: &'a [WorkspaceRelationRecord],
        artifact_positions: Option<&'a [usize]>,
        composition: &'a [WorkspaceRelationRecord],
        composition_positions: Option<&'a [usize]>,
    ) -> Self {
        Self {
            artifact: RelationIter::selected(artifact, artifact_positions).peekable(),
            composition: RelationIter::selected(composition, composition_positions).peekable(),
        }
    }
}

impl<'a> Iterator for MergedRelations<'a> {
    type Item = &'a WorkspaceRelationRecord;

    fn next(&mut self) -> Option<Self::Item> {
        match (self.artifact.peek(), self.composition.peek()) {
            (Some(artifact), Some(composition)) => {
                if workspace_relation_order(artifact, composition).is_le() {
                    self.artifact.next()
                } else {
                    self.composition.next()
                }
            }
            (Some(_), None) => self.artifact.next(),
            (None, Some(_)) => self.composition.next(),
            (None, None) => None,
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.len();
        (len, Some(len))
    }
}

impl ExactSizeIterator for MergedRelations<'_> {
    fn len(&self) -> usize {
        self.artifact.len() + self.composition.len()
    }
}

type WorkspaceRelationIndexes = (
    BTreeMap<WorkspaceRelationRef, usize>,
    BTreeMap<ScopedEntityRef, Vec<usize>>,
    BTreeMap<ScopedEntityRef, Vec<usize>>,
);

fn index_workspace_relations(
    relations: &[WorkspaceRelationRecord],
) -> Result<WorkspaceRelationIndexes, WorkspaceRelationError> {
    let mut by_reference = BTreeMap::new();
    let mut outgoing = BTreeMap::<ScopedEntityRef, Vec<usize>>::new();
    let mut incoming = BTreeMap::<ScopedEntityRef, Vec<usize>>::new();
    for (index, relation) in relations.iter().enumerate() {
        if by_reference
            .insert(relation.relation.clone(), index)
            .is_some()
        {
            return Err(WorkspaceRelationError::DuplicateRelation {
                relation: relation.relation.clone(),
            });
        }
        outgoing
            .entry(relation.from.clone())
            .or_default()
            .push(index);
        incoming.entry(relation.to.clone()).or_default().push(index);
    }
    Ok((by_reference, outgoing, incoming))
}

fn workspace_relation_order(
    left: &WorkspaceRelationRecord,
    right: &WorkspaceRelationRecord,
) -> std::cmp::Ordering {
    left.from
        .cmp(&right.from)
        .then_with(|| left.relation.cmp(&right.relation))
        .then_with(|| left.to.cmp(&right.to))
        .then_with(|| left.source.cmp(&right.source))
}

fn reconstruct_workspace_path(
    from: &ScopedEntityRef,
    to: &ScopedEntityRef,
    predecessor: &BTreeMap<ScopedEntityRef, (ScopedEntityRef, WorkspaceRelationRef)>,
) -> Option<Vec<WorkspaceRelationRef>> {
    let mut current = to.clone();
    let mut reversed = Vec::new();
    while &current != from {
        let (previous, relation) = predecessor.get(&current)?;
        reversed.push(relation.clone());
        current = previous.clone();
    }
    reversed.reverse();
    Some(reversed)
}

/// Structured graph construction, lookup, or selected-path failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WorkspaceRelationError {
    WorkspaceMismatch,
    RootMismatch {
        expected: Box<EvaluationRoot>,
        found: Box<EvaluationRoot>,
    },
    InvalidWorkspaceReference {
        reason: String,
    },
    DuplicateRelation {
        relation: WorkspaceRelationRef,
    },
    UnknownEntity {
        entity: Box<ScopedEntityRef>,
    },
    MissingRelation {
        relation: WorkspaceRelationRef,
    },
    PathDiscontinuity {
        position: usize,
        expected: Box<ScopedEntityRef>,
        found: Box<ScopedEntityRef>,
    },
    PathTargetMismatch {
        expected: Box<ScopedEntityRef>,
        found: Box<ScopedEntityRef>,
    },
}

impl Display for WorkspaceRelationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkspaceMismatch => formatter
                .write_str("workspace relation index belongs to a different exact workspace view"),
            Self::RootMismatch { expected, found } => write!(
                formatter,
                "composition graph belongs to evaluation root {expected:?}, not {found:?}"
            ),
            Self::InvalidWorkspaceReference { reason } => formatter.write_str(reason),
            Self::DuplicateRelation { relation } => {
                write!(
                    formatter,
                    "duplicate workspace relation reference {relation:?}"
                )
            }
            Self::UnknownEntity { entity } => {
                write!(
                    formatter,
                    "workspace graph does not contain entity {entity:?}"
                )
            }
            Self::MissingRelation { relation } => {
                write!(
                    formatter,
                    "workspace graph does not contain relation {relation:?}"
                )
            }
            Self::PathDiscontinuity {
                position,
                expected,
                found,
            } => write!(
                formatter,
                "relation {position} starts at {found:?}, expected {expected:?}"
            ),
            Self::PathTargetMismatch { expected, found } => write!(
                formatter,
                "selected workspace path ends at {found:?}, expected {expected:?}"
            ),
        }
    }
}

impl Error for WorkspaceRelationError {}
