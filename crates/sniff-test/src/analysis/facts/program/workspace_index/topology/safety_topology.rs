//! Unsafe-operation ownership, grouping, source roles, and macro-path validation.

use std::collections::{BTreeMap, BTreeSet};

use super::super::super::super::safety::operations::{
    FunctionEntersUnsafeOperationMacroExpansion, FunctionOwnsUnsafeOperation,
    UnsafeOperationHasSourceAnchor, UnsafeOperationInSafetyEffectGroup, UnsafeOperationKey,
    UnsafeOperationMacroExpansionEntersUnsafeOperationMacroExpansion,
    UnsafeOperationMacroExpansionEntity, UnsafeOperationMacroExpansionHasCallsite,
    UnsafeOperationMacroExpansionKey, UnsafeOperationMacroExpansionProducesUnsafeOperation,
    UnsafeOperationSourceAnchorRole,
};
use super::super::super::super::schema::RowSchema;
use super::super::super::super::view::ArtifactDbView;
use super::super::super::super::workspace::{ArtifactScopeId, ScopedRelationRef};
use super::super::index::{
    ArtifactProgramIndex, WorkspaceProgramIndexError, load_relations, malformed,
};
use super::ArtifactTopology;
use super::macro_paths::require_expected_edges;

pub(super) fn validate(
    scope: &ArtifactScopeId,
    view: ArtifactDbView<'_>,
    entities: &ArtifactProgramIndex,
    topology: &mut ArtifactTopology,
) -> Result<(), WorkspaceProgramIndexError> {
    validate_ownership_and_groups(scope, view, entities, topology)?;
    validate_source_anchors(scope, view, entities, topology)?;
    validate_macro_paths(scope, view, entities, topology)?;
    Ok(())
}

fn validate_ownership_and_groups(
    scope: &ArtifactScopeId,
    view: ArtifactDbView<'_>,
    entities: &ArtifactProgramIndex,
    topology: &mut ArtifactTopology,
) -> Result<(), WorkspaceProgramIndexError> {
    validate_ownership(scope, view, entities, topology)?;
    validate_groups(scope, view, entities, topology)
}

fn validate_ownership(
    scope: &ArtifactScopeId,
    view: ArtifactDbView<'_>,
    entities: &ArtifactProgramIndex,
    topology: &mut ArtifactTopology,
) -> Result<(), WorkspaceProgramIndexError> {
    let mut owners = BTreeMap::<UnsafeOperationKey, super::super::super::FunctionKey>::new();
    for relation in load_relations::<FunctionOwnsUnsafeOperation>(scope, view)? {
        let relation_ref = ScopedRelationRef::new(scope.clone(), relation.relation.clone());
        let owner = entities.functions.key_for_id(
            scope,
            relation.from,
            FunctionOwnsUnsafeOperation::ID,
            "from",
        )?;
        let operation = entities.unsafe_operations.key_for_id(
            scope,
            relation.to,
            FunctionOwnsUnsafeOperation::ID,
            "to",
        )?;
        if operation.owner() != &owner || owners.insert(operation, owner).is_some() {
            return Err(malformed(
                scope,
                FunctionOwnsUnsafeOperation::ID,
                format!("unsafe operation {operation:?} has invalid owning function {owner:?}"),
            ));
        }
        topology
            .unsafe_by_function
            .entry(owner)
            .or_default()
            .push(operation);
        let operation_entity = entities.unsafe_operations.get(&operation).ok_or_else(|| {
            malformed(
                scope,
                FunctionOwnsUnsafeOperation::ID,
                format!("unsafe operation {operation:?} is unavailable after validation"),
            )
        })?;
        topology
            .unsafe_operation_edges_by_function
            .entry(owner)
            .or_default()
            .push(super::IndexedUnsafeOperation::new(
                operation,
                operation_entity.id(),
                relation_ref,
            ));
    }
    for operation in entities.unsafe_operations.by_key.keys() {
        if !owners.contains_key(operation) {
            return Err(malformed(
                scope,
                FunctionOwnsUnsafeOperation::ID,
                format!("unsafe operation {operation:?} has no owning function"),
            ));
        }
    }
    for operations in topology.unsafe_by_function.values_mut() {
        operations.sort_unstable();
    }
    for operations in topology.unsafe_operation_edges_by_function.values_mut() {
        operations.sort_unstable_by_key(super::IndexedUnsafeOperation::operation);
    }
    let mut next_local_id = BTreeMap::new();
    for operation in entities.unsafe_operations.by_key.keys() {
        let expected = next_local_id.entry(*operation.owner()).or_insert(0_u32);
        if operation.local_id() != *expected {
            return Err(malformed(
                scope,
                FunctionOwnsUnsafeOperation::ID,
                format!(
                    "unsafe operation {operation:?} is noncontiguous; expected local id {expected}"
                ),
            ));
        }
        *expected = expected.checked_add(1).ok_or_else(|| {
            malformed(
                scope,
                FunctionOwnsUnsafeOperation::ID,
                format!("unsafe operation ids overflow for {:?}", operation.owner()),
            )
        })?;
    }

    Ok(())
}

fn validate_groups(
    scope: &ArtifactScopeId,
    view: ArtifactDbView<'_>,
    entities: &ArtifactProgramIndex,
    topology: &mut ArtifactTopology,
) -> Result<(), WorkspaceProgramIndexError> {
    let mut groups = BTreeMap::new();
    for relation in load_relations::<UnsafeOperationInSafetyEffectGroup>(scope, view)? {
        let relation_ref = ScopedRelationRef::new(scope.clone(), relation.relation.clone());
        let operation = entities.unsafe_operations.key_for_id(
            scope,
            relation.from,
            UnsafeOperationInSafetyEffectGroup::ID,
            "from",
        )?;
        let group = entities.safety_groups.key_for_id(
            scope,
            relation.to,
            UnsafeOperationInSafetyEffectGroup::ID,
            "to",
        )?;
        if operation.owner() != group.owner() || groups.insert(operation, group).is_some() {
            return Err(malformed(
                scope,
                UnsafeOperationInSafetyEffectGroup::ID,
                format!("unsafe operation {operation:?} has invalid safety group {group:?}"),
            ));
        }
        topology.unsafe_groups.insert(operation, group);
        let group_entity = entities.safety_groups.get(&group).ok_or_else(|| {
            malformed(
                scope,
                UnsafeOperationInSafetyEffectGroup::ID,
                format!("unsafe operation {operation:?} safety group is unavailable"),
            )
        })?;
        topology.unsafe_group_edges.insert(
            operation,
            super::IndexedUnsafeOperationSafetyGroup::new(group_entity.clone(), relation_ref),
        );
    }
    for operation in entities.unsafe_operations.by_key.keys() {
        if !groups.contains_key(operation) {
            return Err(malformed(
                scope,
                UnsafeOperationInSafetyEffectGroup::ID,
                format!("unsafe operation {operation:?} has no safety group"),
            ));
        }
    }
    Ok(())
}

fn validate_source_anchors(
    scope: &ArtifactScopeId,
    view: ArtifactDbView<'_>,
    entities: &ArtifactProgramIndex,
    topology: &mut ArtifactTopology,
) -> Result<(), WorkspaceProgramIndexError> {
    let mut roles = BTreeSet::<(UnsafeOperationKey, UnsafeOperationSourceAnchorRole)>::new();
    for relation in load_relations::<UnsafeOperationHasSourceAnchor>(scope, view)? {
        let relation_ref = ScopedRelationRef::new(scope.clone(), relation.relation.clone());
        let operation = entities.unsafe_operations.key_for_id(
            scope,
            relation.from,
            UnsafeOperationHasSourceAnchor::ID,
            "from",
        )?;
        let anchor = entities.source_anchors.entity_for_id(
            scope,
            relation.to,
            UnsafeOperationHasSourceAnchor::ID,
            "to",
        )?;
        let role = relation.data.role();
        if !roles.insert((operation, role)) {
            return Err(malformed(
                scope,
                UnsafeOperationHasSourceAnchor::ID,
                format!(
                    "unsafe operation {operation:?} repeats source role {:?}",
                    relation.data.role()
                ),
            ));
        }
        topology
            .source_anchors_by_unsafe_operation
            .entry(operation)
            .or_default()
            .push(super::IndexedUnsafeOperationSourceAnchor::new(
                role,
                anchor.data().anchor().clone(),
                anchor.id(),
                relation_ref,
            ));
    }
    for anchors in topology.source_anchors_by_unsafe_operation.values_mut() {
        anchors.sort_unstable_by_key(super::IndexedUnsafeOperationSourceAnchor::role);
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the three unsafe macro relations form one atomic path invariant"
)]
fn validate_macro_paths(
    scope: &ArtifactScopeId,
    view: ArtifactDbView<'_>,
    entities: &ArtifactProgramIndex,
    topology: &mut ArtifactTopology,
) -> Result<(), WorkspaceProgramIndexError> {
    let mut frames = BTreeMap::<UnsafeOperationKey, Vec<UnsafeOperationMacroExpansionKey>>::new();
    for entity in entities.unsafe_macros.by_key.values() {
        let frame = entity.data();
        let key = *frame.key();
        if entities.unsafe_operations.get(key.operation()).is_none()
            || frame.display_path().is_empty()
        {
            return Err(malformed(
                scope,
                UnsafeOperationMacroExpansionEntity::ID,
                format!("unsafe macro frame {key:?} has an invalid endpoint or display path"),
            ));
        }
        frames.entry(*key.operation()).or_default().push(key);
    }

    let mut expected_entries = BTreeSet::new();
    let mut expected_links = BTreeSet::new();
    let mut expected_exits = BTreeSet::new();
    for (operation, path) in &mut frames {
        path.sort_unstable();
        let mut hashes = BTreeSet::new();
        let mut ordered_hashes = Vec::with_capacity(path.len());
        for (expected_depth, key) in (0_u32..).zip(path.iter()) {
            let frame = entities.unsafe_macros.get(key).ok_or_else(|| {
                malformed(
                    scope,
                    UnsafeOperationMacroExpansionEntity::ID,
                    format!("unsafe macro frame {key:?} disappeared during indexing"),
                )
            })?;
            if key.depth() != expected_depth || !hashes.insert(frame.data().expansion_hash()) {
                return Err(malformed(
                    scope,
                    UnsafeOperationMacroExpansionEntity::ID,
                    format!(
                        "unsafe macro path for {operation:?} is noncontiguous or repeats a hash"
                    ),
                ));
            }
            ordered_hashes.push(frame.data().expansion_hash());
        }
        if let (Some(first), Some(last)) = (path.first(), path.last()) {
            expected_entries.insert((*operation.owner(), *first));
            expected_exits.insert((*last, *operation));
            expected_links.extend(path.windows(2).map(|pair| (pair[0], pair[1])));
        }
        topology
            .unsafe_macro_paths
            .insert(*operation, ordered_hashes);
    }

    let actual_entry_rows =
        load_relations::<FunctionEntersUnsafeOperationMacroExpansion>(scope, view)?;
    let actual_entry_count = actual_entry_rows.len();
    let mut entry_refs = BTreeMap::new();
    for relation in actual_entry_rows {
        let edge = (
            entities.functions.key_for_id(
                scope,
                relation.from,
                FunctionEntersUnsafeOperationMacroExpansion::ID,
                "from",
            )?,
            entities.unsafe_macros.key_for_id(
                scope,
                relation.to,
                FunctionEntersUnsafeOperationMacroExpansion::ID,
                "to",
            )?,
        );
        if entry_refs
            .insert(
                edge,
                ScopedRelationRef::new(scope.clone(), relation.relation),
            )
            .is_some()
        {
            return Err(malformed(
                scope,
                FunctionEntersUnsafeOperationMacroExpansion::ID,
                format!("duplicate unsafe macro entry edge {edge:?}"),
            ));
        }
    }
    let actual_entries = entry_refs.keys().copied().collect::<BTreeSet<_>>();
    let actual_link_rows = load_relations::<
        UnsafeOperationMacroExpansionEntersUnsafeOperationMacroExpansion,
    >(scope, view)?;
    let actual_link_count = actual_link_rows.len();
    let mut link_refs = BTreeMap::new();
    for relation in actual_link_rows {
        let edge = (
            entities.unsafe_macros.key_for_id(
                scope,
                relation.from,
                UnsafeOperationMacroExpansionEntersUnsafeOperationMacroExpansion::ID,
                "from",
            )?,
            entities.unsafe_macros.key_for_id(
                scope,
                relation.to,
                UnsafeOperationMacroExpansionEntersUnsafeOperationMacroExpansion::ID,
                "to",
            )?,
        );
        if link_refs
            .insert(
                edge,
                ScopedRelationRef::new(scope.clone(), relation.relation),
            )
            .is_some()
        {
            return Err(malformed(
                scope,
                UnsafeOperationMacroExpansionEntersUnsafeOperationMacroExpansion::ID,
                format!("duplicate unsafe macro link edge {edge:?}"),
            ));
        }
    }
    let actual_links = link_refs.keys().copied().collect::<BTreeSet<_>>();
    let actual_exit_rows =
        load_relations::<UnsafeOperationMacroExpansionProducesUnsafeOperation>(scope, view)?;
    let actual_exit_count = actual_exit_rows.len();
    let mut exit_refs = BTreeMap::new();
    for relation in actual_exit_rows {
        let edge = (
            entities.unsafe_macros.key_for_id(
                scope,
                relation.from,
                UnsafeOperationMacroExpansionProducesUnsafeOperation::ID,
                "from",
            )?,
            entities.unsafe_operations.key_for_id(
                scope,
                relation.to,
                UnsafeOperationMacroExpansionProducesUnsafeOperation::ID,
                "to",
            )?,
        );
        if exit_refs
            .insert(
                edge,
                ScopedRelationRef::new(scope.clone(), relation.relation),
            )
            .is_some()
        {
            return Err(malformed(
                scope,
                UnsafeOperationMacroExpansionProducesUnsafeOperation::ID,
                format!("duplicate unsafe macro exit edge {edge:?}"),
            ));
        }
    }
    let actual_exits = exit_refs.keys().copied().collect::<BTreeSet<_>>();
    require_expected_edges(
        scope,
        FunctionEntersUnsafeOperationMacroExpansion::ID,
        &actual_entries,
        &expected_entries,
        actual_entry_count,
    )?;
    require_expected_edges(
        scope,
        UnsafeOperationMacroExpansionEntersUnsafeOperationMacroExpansion::ID,
        &actual_links,
        &expected_links,
        actual_link_count,
    )?;
    require_expected_edges(
        scope,
        UnsafeOperationMacroExpansionProducesUnsafeOperation::ID,
        &actual_exits,
        &expected_exits,
        actual_exit_count,
    )?;
    let macro_callsites = index_macro_callsites(scope, view, entities)?;
    for (operation, path) in frames {
        let (Some(first), Some(last)) = (path.first(), path.last()) else {
            continue;
        };
        let entry = entry_refs
            .get(&(*operation.owner(), *first))
            .ok_or_else(|| {
                malformed(
                    scope,
                    FunctionEntersUnsafeOperationMacroExpansion::ID,
                    format!("validated unsafe macro entry for {operation:?} is unavailable"),
                )
            })?
            .clone();
        let mut links = Vec::with_capacity(path.len().saturating_sub(1));
        for pair in path.windows(2) {
            links.push(
                link_refs
                    .get(&(pair[0], pair[1]))
                    .ok_or_else(|| {
                        malformed(
                            scope,
                            UnsafeOperationMacroExpansionEntersUnsafeOperationMacroExpansion::ID,
                            format!("validated unsafe macro link {pair:?} is unavailable"),
                        )
                    })?
                    .clone(),
            );
        }
        let exit = exit_refs
            .get(&(*last, operation))
            .ok_or_else(|| {
                malformed(
                    scope,
                    UnsafeOperationMacroExpansionProducesUnsafeOperation::ID,
                    format!("validated unsafe macro exit for {operation:?} is unavailable"),
                )
            })?
            .clone();
        let mut frame_entities = Vec::with_capacity(path.len());
        let mut callsites = Vec::with_capacity(path.len());
        for key in path {
            frame_entities.push(entities.unsafe_macros.get(&key).cloned().ok_or_else(|| {
                malformed(
                    scope,
                    UnsafeOperationMacroExpansionEntity::ID,
                    format!("validated unsafe macro frame {key:?} is unavailable"),
                )
            })?);
            callsites.push(macro_callsites.get(&key).cloned());
        }
        topology.indexed_unsafe_macro_paths.insert(
            operation,
            super::IndexedUnsafeOperationMacroPath::new(
                frame_entities,
                entry,
                links,
                exit,
                callsites,
            ),
        );
    }
    Ok(())
}

fn index_macro_callsites(
    scope: &ArtifactScopeId,
    view: ArtifactDbView<'_>,
    entities: &ArtifactProgramIndex,
) -> Result<
    BTreeMap<UnsafeOperationMacroExpansionKey, super::IndexedUnsafeOperationMacroCallsite>,
    WorkspaceProgramIndexError,
> {
    let mut callsites = BTreeMap::new();
    for relation in load_relations::<UnsafeOperationMacroExpansionHasCallsite>(scope, view)? {
        let frame = entities.unsafe_macros.key_for_id(
            scope,
            relation.from,
            UnsafeOperationMacroExpansionHasCallsite::ID,
            "from",
        )?;
        let anchor = entities.source_anchors.entity_for_id(
            scope,
            relation.to,
            UnsafeOperationMacroExpansionHasCallsite::ID,
            "to",
        )?;
        let callsite = super::IndexedUnsafeOperationMacroCallsite::new(
            anchor.data().anchor().clone(),
            anchor.id(),
            ScopedRelationRef::new(scope.clone(), relation.relation),
        );
        if callsites.insert(frame, callsite).is_some() {
            return Err(malformed(
                scope,
                UnsafeOperationMacroExpansionHasCallsite::ID,
                format!("unsafe macro frame {frame:?} has multiple invocation anchors"),
            ));
        }
    }
    Ok(callsites)
}
