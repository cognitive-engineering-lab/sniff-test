//! Generic adjacency and path selection over persisted provenance relations.
//!
//! The graph deliberately does not consult the schema registry. Unknown relation
//! schemas remain valid provenance edges and are therefore indexed alongside
//! registered schemas. Canonical relation-reference order makes adjacency and
//! shortest-path tie breaking independent of serialized index order.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use super::encoded::{EntityRef, RelationIndexRow, RowRef};
use super::view::ArtifactDbView;

/// Read-only adjacency index for every relation in one artifact database.
#[derive(Debug, Clone)]
pub(crate) struct RelationGraph {
    relations: Vec<RelationIndexRow>,
    outgoing: BTreeMap<EntityRef, Vec<usize>>,
    incoming: BTreeMap<EntityRef, Vec<usize>>,
}

impl RelationGraph {
    /// Builds a canonical graph from the artifact's complete relation index.
    #[must_use]
    pub(crate) fn new(view: ArtifactDbView<'_>) -> Self {
        Self::build(&view.artifact().relation_index)
    }

    fn build(index: &[RelationIndexRow]) -> Self {
        let mut relations = index.to_vec();
        relations.sort_by(canonical_relation_order);

        let mut outgoing = BTreeMap::<EntityRef, Vec<usize>>::new();
        let mut incoming = BTreeMap::<EntityRef, Vec<usize>>::new();
        for (index, relation) in relations.iter().enumerate() {
            outgoing
                .entry(relation.from.clone())
                .or_default()
                .push(index);
            incoming.entry(relation.to.clone()).or_default().push(index);
        }

        Self {
            relations,
            outgoing,
            incoming,
        }
    }

    /// Returns all relations in canonical relation-reference order.
    pub(crate) fn relations(&self) -> impl ExactSizeIterator<Item = &RelationIndexRow> {
        self.relations.iter()
    }

    /// Returns canonically ordered relations leaving `entity`.
    pub(crate) fn outgoing(&self, entity: &EntityRef) -> impl Iterator<Item = &RelationIndexRow> {
        self.outgoing
            .get(entity)
            .into_iter()
            .flatten()
            .map(|index| &self.relations[*index])
    }

    /// Returns canonically ordered relations entering `entity`.
    pub(crate) fn incoming(&self, entity: &EntityRef) -> impl Iterator<Item = &RelationIndexRow> {
        self.incoming
            .get(entity)
            .into_iter()
            .flatten()
            .map(|index| &self.relations[*index])
    }

    /// Selects a deterministic shortest directed path between two entities.
    ///
    /// When several paths have the same length, breadth-first traversal of
    /// canonically ordered outgoing relations selects the lexicographically
    /// smallest relation-reference path. A path from an entity to itself is the
    /// empty path.
    #[must_use]
    pub(crate) fn shortest_path(&self, from: &EntityRef, to: &EntityRef) -> Option<Vec<RowRef>> {
        if from == to {
            return Some(Vec::new());
        }

        let mut reached = BTreeSet::from([from.clone()]);
        let mut predecessor = BTreeMap::<EntityRef, (EntityRef, RowRef)>::new();
        let mut pending = VecDeque::from([from.clone()]);

        while let Some(entity) = pending.pop_front() {
            for relation in self.outgoing(&entity) {
                let target = relation.to.clone();
                if !reached.insert(target.clone()) {
                    continue;
                }
                predecessor.insert(
                    target.clone(),
                    (entity.clone(), relation_reference(relation)),
                );
                if &target == to {
                    return reconstruct_path(from, to, &predecessor);
                }
                pending.push_back(target);
            }
        }

        None
    }
}

fn reconstruct_path(
    from: &EntityRef,
    to: &EntityRef,
    predecessor: &BTreeMap<EntityRef, (EntityRef, RowRef)>,
) -> Option<Vec<RowRef>> {
    let mut current = to;
    let mut path = Vec::new();
    while current != from {
        let (previous, relation) = predecessor.get(current)?;
        path.push(relation.clone());
        current = previous;
    }
    path.reverse();
    Some(path)
}

fn relation_reference(relation: &RelationIndexRow) -> RowRef {
    relation.relation.clone()
}

fn canonical_relation_order(
    left: &RelationIndexRow,
    right: &RelationIndexRow,
) -> std::cmp::Ordering {
    relation_reference(left)
        .cmp(&relation_reference(right))
        .then_with(|| left.from.cmp(&right.from))
        .then_with(|| left.to.cmp(&right.to))
        .then_with(|| left.source.cmp(&right.source))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::*;
    use crate::analysis::facts::encoded::{
        ArtifactFactIr, EncodedRow, EncodedTable, FACT_IR_FORMAT_VERSION, TableKind,
    };
    use crate::analysis::facts::registry::SchemaRegistry;
    use crate::analysis::facts::schema::SchemaId;

    fn schema(id: &str) -> SchemaId {
        SchemaId::new(id).expect("valid test schema ID")
    }

    fn entity(row: u32) -> EntityRef {
        EntityRef {
            schema: schema("sample.node"),
            row,
        }
    }

    fn relation(schema_id: &str, row: u32, from: u32, to: u32) -> RelationIndexRow {
        RelationIndexRow {
            relation: RowRef {
                schema: schema(schema_id),
                row,
            },
            from: entity(from),
            to: entity(to),
            source: None,
        }
    }

    fn graph(mut relations: Vec<RelationIndexRow>) -> RelationGraph {
        let mut relation_tables = BTreeMap::<SchemaId, Vec<EncodedRow>>::new();
        for relation in &relations {
            let rows = relation_tables
                .entry(relation.relation.schema.clone())
                .or_default();
            assert_eq!(relation.relation.row as usize, rows.len());
            rows.push(EncodedRow {
                stable_key: None,
                data: json!({}),
            });
        }

        let mut tables = relation_tables
            .into_iter()
            .map(|(schema, rows)| EncodedTable {
                schema,
                version: 1,
                kind: TableKind::Relation,
                rows,
            })
            .collect::<Vec<_>>();
        tables.push(EncodedTable {
            schema: schema("sample.node"),
            version: 1,
            kind: TableKind::Entity,
            rows: (0..=3)
                .map(|row| EncodedRow {
                    stable_key: Some(json!(format!("{row:04}"))),
                    data: json!({ "row": row }),
                })
                .collect(),
        });
        tables.sort_by(|left, right| left.schema.cmp(&right.schema));
        relations.sort();
        let artifact = ArtifactFactIr {
            format_version: FACT_IR_FORMAT_VERSION,
            tables,
            fact_index: Vec::new(),
            relation_index: relations,
        };
        let schemas = SchemaRegistry::new();
        let view = ArtifactDbView::open(&artifact, &schemas).unwrap();
        RelationGraph::new(view)
    }

    #[test]
    fn indexes_all_schemas_in_canonical_relation_order() {
        let graph = graph(vec![
            relation("sample.edge", 0, 0, 1),
            relation("sample.edge", 1, 1, 3),
            relation("sample.edge", 2, 2, 3),
            relation("future.allocator-edge", 0, 0, 2),
        ]);

        let all = graph
            .relations()
            .map(|edge| edge.relation.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            all,
            vec![
                RowRef {
                    schema: schema("future.allocator-edge"),
                    row: 0,
                },
                RowRef {
                    schema: schema("sample.edge"),
                    row: 0,
                },
                RowRef {
                    schema: schema("sample.edge"),
                    row: 1,
                },
                RowRef {
                    schema: schema("sample.edge"),
                    row: 2,
                },
            ]
        );

        let outgoing = graph
            .outgoing(&entity(0))
            .map(|edge| edge.relation.clone())
            .collect::<Vec<_>>();
        assert_eq!(outgoing, vec![all[0].clone(), all[1].clone()]);

        let incoming = graph
            .incoming(&entity(3))
            .map(|edge| edge.relation.clone())
            .collect::<Vec<_>>();
        assert_eq!(incoming, vec![all[2].clone(), all[3].clone()]);
    }

    #[test]
    fn shortest_path_has_deterministic_tie_breaking_and_handles_cycles() {
        let graph = graph(vec![
            relation("sample.edge", 0, 0, 1),
            relation("sample.edge", 1, 0, 2),
            relation("sample.edge", 2, 1, 3),
            relation("sample.edge", 3, 2, 0),
            relation("sample.edge", 4, 2, 3),
        ]);

        assert_eq!(
            graph.shortest_path(&entity(0), &entity(3)),
            Some(vec![
                RowRef {
                    schema: schema("sample.edge"),
                    row: 0,
                },
                RowRef {
                    schema: schema("sample.edge"),
                    row: 2,
                },
            ])
        );
        assert_eq!(
            graph.shortest_path(&entity(0), &entity(0)),
            Some(Vec::new())
        );
        assert_eq!(graph.shortest_path(&entity(0), &entity(9)), None);
    }
}
