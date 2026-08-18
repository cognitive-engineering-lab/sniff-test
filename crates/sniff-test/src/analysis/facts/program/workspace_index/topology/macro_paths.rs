//! Exact call/effect source roles and outer-to-inner macro-path validation.

use std::collections::{BTreeMap, BTreeSet};

use super::super::super::super::schema::RowSchema;
use super::super::super::super::view::ArtifactDbView;
use super::super::super::super::workspace::{ArtifactScopeId, ScopedRelationRef};
use super::super::super::topology::{
    CallMacroExpansionEntersCallMacroExpansion, CallMacroExpansionHasCallsite,
    CallMacroExpansionKey, CallMacroExpansionProducesCallOccurrence, CallOccurrenceHasSourceAnchor,
    CallOccurrenceKey, CallSourceAnchorRole, FunctionEntersCallMacroExpansion,
};
use super::super::super::{
    EffectSiteHasSourceAnchor, EffectSiteKey, EffectSourceAnchorRole, FunctionEntersMacroExpansion,
    FunctionOwnsEffectSite, MacroExpansionEntersMacroExpansion, MacroExpansionHasCallsite,
    MacroExpansionKey, MacroExpansionProducesEffectSite,
};
use super::super::index::{
    ArtifactProgramIndex, EntityTable, WorkspaceProgramIndexError, load_relations, malformed,
};
use super::ArtifactTopology;

pub(super) fn validate(
    scope: &ArtifactScopeId,
    view: ArtifactDbView<'_>,
    entities: &ArtifactProgramIndex,
    topology: &mut ArtifactTopology,
) -> Result<(), WorkspaceProgramIndexError> {
    validate_call_source_anchors(scope, view, entities, topology)?;
    validate_call_macro_paths(scope, view, entities, topology)?;
    validate_effects(scope, view, entities, topology)
}

fn validate_call_source_anchors(
    scope: &ArtifactScopeId,
    view: ArtifactDbView<'_>,
    entities: &ArtifactProgramIndex,
    topology: &mut ArtifactTopology,
) -> Result<(), WorkspaceProgramIndexError> {
    let mut roles = BTreeSet::<(CallOccurrenceKey, CallSourceAnchorRole)>::new();
    for relation in load_relations::<CallOccurrenceHasSourceAnchor>(scope, view)? {
        let relation_ref = ScopedRelationRef::new(scope.clone(), relation.relation.clone());
        let occurrence = entities.occurrences.key_for_id(
            scope,
            relation.from,
            CallOccurrenceHasSourceAnchor::ID,
            "from",
        )?;
        let anchor_key = entities.source_anchors.key_for_id(
            scope,
            relation.to,
            CallOccurrenceHasSourceAnchor::ID,
            "to",
        )?;
        let anchor = entities
            .source_anchors
            .get(&anchor_key)
            .expect("source-anchor row and key indexes are built atomically");
        let role = relation.data.role();
        if !roles.insert((occurrence, role)) {
            return Err(malformed(
                scope,
                CallOccurrenceHasSourceAnchor::ID,
                format!("call occurrence {occurrence:?} repeats source role {role:?}"),
            ));
        }
        topology
            .source_anchors_by_occurrence
            .entry(occurrence)
            .or_default()
            .push(super::IndexedCallSourceAnchor::new(
                role,
                anchor_key,
                anchor.id(),
                relation_ref,
            ));
    }
    for anchors in topology.source_anchors_by_occurrence.values_mut() {
        anchors.sort_unstable_by_key(super::IndexedCallSourceAnchor::role);
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the three call-macro relation tables form one atomic path invariant"
)]
fn validate_call_macro_paths(
    scope: &ArtifactScopeId,
    view: ArtifactDbView<'_>,
    entities: &ArtifactProgramIndex,
    topology: &mut ArtifactTopology,
) -> Result<(), WorkspaceProgramIndexError> {
    let mut frames = BTreeMap::<CallOccurrenceKey, Vec<CallMacroExpansionKey>>::new();
    for entity in entities.call_macros.by_key.values() {
        let frame = entity.data();
        let key = *frame.key();
        if entities.occurrences.get(key.occurrence()).is_none() || frame.display_path().is_empty() {
            return Err(malformed(
                scope,
                super::super::super::topology::CallMacroExpansionEntity::ID,
                format!("call macro frame {key:?} has an invalid endpoint or display path"),
            ));
        }
        frames.entry(*key.occurrence()).or_default().push(key);
    }

    let mut expected_entries = BTreeSet::new();
    let mut expected_links = BTreeSet::new();
    let mut expected_exits = BTreeSet::new();
    for (occurrence, path) in &mut frames {
        path.sort_unstable();
        let mut hashes = BTreeSet::new();
        for (expected_depth, key) in (0_u32..).zip(path.iter()) {
            let frame = entities
                .call_macros
                .get(key)
                .expect("macro key came from the entity table");
            if key.depth() != expected_depth || !hashes.insert(frame.data().expansion_hash()) {
                return Err(malformed(
                    scope,
                    super::super::super::topology::CallMacroExpansionEntity::ID,
                    format!(
                        "call macro path for {occurrence:?} is noncontiguous or repeats a hash"
                    ),
                ));
            }
        }
        let owner = *occurrence.owner();
        if entities.functions.get(&owner).is_none() {
            return Err(malformed(
                scope,
                FunctionEntersCallMacroExpansion::ID,
                format!("call macro path for {occurrence:?} has no owning body"),
            ));
        }
        if let Some(first) = path.first() {
            expected_entries.insert((owner, *first));
            expected_exits.insert((*path.last().expect("nonempty path"), *occurrence));
            expected_links.extend(path.windows(2).map(|pair| (pair[0], pair[1])));
        }
        topology.call_macro_paths.insert(
            *occurrence,
            path.iter()
                .map(|key| {
                    entities
                        .call_macros
                        .get(key)
                        .expect("macro key came from the entity table")
                        .data()
                        .expansion_hash()
                })
                .collect(),
        );
    }

    let actual_entry_rows = load_relations::<FunctionEntersCallMacroExpansion>(scope, view)?;
    let actual_entry_count = actual_entry_rows.len();
    let mut entry_refs = BTreeMap::new();
    for relation in actual_entry_rows {
        let edge = (
            entities.functions.key_for_id(
                scope,
                relation.from,
                FunctionEntersCallMacroExpansion::ID,
                "from",
            )?,
            entities.call_macros.key_for_id(
                scope,
                relation.to,
                FunctionEntersCallMacroExpansion::ID,
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
                FunctionEntersCallMacroExpansion::ID,
                format!("duplicate call macro entry edge {edge:?}"),
            ));
        }
    }
    let actual_entries = entry_refs.keys().copied().collect::<BTreeSet<_>>();
    let actual_link_rows =
        load_relations::<CallMacroExpansionEntersCallMacroExpansion>(scope, view)?;
    let actual_link_count = actual_link_rows.len();
    let mut link_refs = BTreeMap::new();
    for relation in actual_link_rows {
        let edge = (
            entities.call_macros.key_for_id(
                scope,
                relation.from,
                CallMacroExpansionEntersCallMacroExpansion::ID,
                "from",
            )?,
            entities.call_macros.key_for_id(
                scope,
                relation.to,
                CallMacroExpansionEntersCallMacroExpansion::ID,
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
                CallMacroExpansionEntersCallMacroExpansion::ID,
                format!("duplicate call macro link edge {edge:?}"),
            ));
        }
    }
    let actual_links = link_refs.keys().copied().collect::<BTreeSet<_>>();
    let actual_exit_rows = load_relations::<CallMacroExpansionProducesCallOccurrence>(scope, view)?;
    let actual_exit_count = actual_exit_rows.len();
    let mut exit_refs = BTreeMap::new();
    for relation in actual_exit_rows {
        let edge = (
            entities.call_macros.key_for_id(
                scope,
                relation.from,
                CallMacroExpansionProducesCallOccurrence::ID,
                "from",
            )?,
            entities.occurrences.key_for_id(
                scope,
                relation.to,
                CallMacroExpansionProducesCallOccurrence::ID,
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
                CallMacroExpansionProducesCallOccurrence::ID,
                format!("duplicate call macro exit edge {edge:?}"),
            ));
        }
    }
    let actual_exits = exit_refs.keys().copied().collect::<BTreeSet<_>>();
    require_expected_edges(
        scope,
        FunctionEntersCallMacroExpansion::ID,
        &actual_entries,
        &expected_entries,
        actual_entry_count,
    )?;
    require_expected_edges(
        scope,
        CallMacroExpansionEntersCallMacroExpansion::ID,
        &actual_links,
        &expected_links,
        actual_link_count,
    )?;
    require_expected_edges(
        scope,
        CallMacroExpansionProducesCallOccurrence::ID,
        &actual_exits,
        &expected_exits,
        actual_exit_count,
    )?;
    let macro_callsites = index_call_macro_callsites(scope, view, entities)?;
    for (occurrence, path) in frames {
        let Some(first) = path.first().copied() else {
            continue;
        };
        let owner = *occurrence.owner();
        let entry = entry_refs
            .get(&(owner, first))
            .expect("validated call macro entry is present")
            .clone();
        let links = path
            .windows(2)
            .map(|pair| {
                link_refs
                    .get(&(pair[0], pair[1]))
                    .expect("validated call macro link is present")
                    .clone()
            })
            .collect();
        let exit = exit_refs
            .get(&(*path.last().expect("nonempty path"), occurrence))
            .expect("validated call macro exit is present")
            .clone();
        let frame_entities = path
            .iter()
            .map(|key| {
                entities
                    .call_macros
                    .get(key)
                    .expect("macro key came from the entity table")
                    .clone()
            })
            .collect();
        let callsites = path
            .iter()
            .map(|key| macro_callsites.get(key).cloned())
            .collect();
        topology.indexed_call_macro_paths.insert(
            occurrence,
            super::IndexedCallMacroPath::new(frame_entities, entry, links, exit, callsites),
        );
    }
    Ok(())
}

fn index_call_macro_callsites(
    scope: &ArtifactScopeId,
    view: ArtifactDbView<'_>,
    entities: &ArtifactProgramIndex,
) -> Result<
    BTreeMap<CallMacroExpansionKey, super::IndexedCallMacroCallsite>,
    WorkspaceProgramIndexError,
> {
    let mut callsites = BTreeMap::new();
    for relation in load_relations::<CallMacroExpansionHasCallsite>(scope, view)? {
        let frame = entities.call_macros.key_for_id(
            scope,
            relation.from,
            CallMacroExpansionHasCallsite::ID,
            "from",
        )?;
        let anchor = entities.source_anchors.entity_for_id(
            scope,
            relation.to,
            CallMacroExpansionHasCallsite::ID,
            "to",
        )?;
        let callsite = super::IndexedCallMacroCallsite::new(
            anchor.data().anchor().clone(),
            anchor.id(),
            ScopedRelationRef::new(scope.clone(), relation.relation),
        );
        if callsites.insert(frame, callsite).is_some() {
            return Err(malformed(
                scope,
                CallMacroExpansionHasCallsite::ID,
                format!("call macro frame {frame:?} has multiple invocation anchors"),
            ));
        }
    }
    Ok(callsites)
}

#[allow(
    clippy::too_many_lines,
    reason = "effect ownership and its three macro relation tables are one atomic path invariant"
)]
fn validate_effects(
    scope: &ArtifactScopeId,
    view: ArtifactDbView<'_>,
    entities: &ArtifactProgramIndex,
    topology: &mut ArtifactTopology,
) -> Result<(), WorkspaceProgramIndexError> {
    let mut owners = BTreeMap::<EffectSiteKey, super::super::super::FunctionKey>::new();
    for relation in load_relations::<FunctionOwnsEffectSite>(scope, view)? {
        let relation_ref = ScopedRelationRef::new(scope.clone(), relation.relation.clone());
        let owner = entities.functions.key_for_id(
            scope,
            relation.from,
            FunctionOwnsEffectSite::ID,
            "from",
        )?;
        let effect =
            entities
                .effects
                .key_for_id(scope, relation.to, FunctionOwnsEffectSite::ID, "to")?;
        if effect.function() != &owner || owners.insert(effect, owner).is_some() {
            return Err(malformed(
                scope,
                FunctionOwnsEffectSite::ID,
                format!("effect {effect:?} has invalid owning function {owner:?}"),
            ));
        }
        topology
            .effects_by_function
            .entry(owner)
            .or_default()
            .push(effect);
        let effect_entity = entities
            .effects
            .get(&effect)
            .expect("effect row and key indexes are built atomically");
        topology
            .effect_site_edges_by_function
            .entry(owner)
            .or_default()
            .push(super::IndexedEffectSite::new(
                effect,
                effect_entity.id(),
                relation_ref,
            ));
    }
    for effect in entities.effects.by_key.keys() {
        if !owners.contains_key(effect) {
            return Err(malformed(
                scope,
                FunctionOwnsEffectSite::ID,
                format!("effect {effect:?} has no owning function"),
            ));
        }
    }
    for effects in topology.effects_by_function.values_mut() {
        effects.sort_unstable();
    }
    for effects in topology.effect_site_edges_by_function.values_mut() {
        effects.sort_unstable_by_key(super::IndexedEffectSite::site);
    }

    let mut roles = BTreeSet::<(EffectSiteKey, u8)>::new();
    for relation in load_relations::<EffectSiteHasSourceAnchor>(scope, view)? {
        let relation_ref = ScopedRelationRef::new(scope.clone(), relation.relation.clone());
        let effect = entities.effects.key_for_id(
            scope,
            relation.from,
            EffectSiteHasSourceAnchor::ID,
            "from",
        )?;
        let anchor = entities.source_anchors.entity_for_id(
            scope,
            relation.to,
            EffectSiteHasSourceAnchor::ID,
            "to",
        )?;
        let role = relation.data.role();
        if !roles.insert((effect, effect_source_role_order(role))) {
            return Err(malformed(
                scope,
                EffectSiteHasSourceAnchor::ID,
                format!(
                    "effect {effect:?} repeats source role {:?}",
                    relation.data.role()
                ),
            ));
        }
        topology
            .source_anchors_by_effect
            .entry(effect)
            .or_default()
            .push(super::IndexedEffectSourceAnchor::new(
                role,
                anchor.data().anchor().clone(),
                anchor.id(),
                relation_ref,
            ));
    }
    for anchors in topology.source_anchors_by_effect.values_mut() {
        anchors.sort_unstable_by_key(|anchor| effect_source_role_order(anchor.role()));
    }

    let mut frames = BTreeMap::<EffectSiteKey, Vec<MacroExpansionKey>>::new();
    for entity in entities.effect_macros.by_key.values() {
        let key = entity.data().expansion().clone();
        if entities.effects.get(key.effect_site()).is_none()
            || entity.data().display_path().is_empty()
        {
            return Err(malformed(
                scope,
                super::super::super::MacroExpansionEntity::ID,
                format!("effect macro frame {key:?} has an invalid endpoint or display path"),
            ));
        }
        frames.entry(*key.effect_site()).or_default().push(key);
    }

    let mut expected_entries = BTreeSet::new();
    let mut expected_links = BTreeSet::new();
    let mut expected_exits = BTreeSet::new();
    for (effect, path) in &mut frames {
        path.sort();
        let mut hashes = BTreeSet::new();
        for (expected_depth, key) in (0_u32..).zip(path.iter()) {
            let frame = entities.effect_macros.get(key).expect("indexed macro key");
            if key.depth() != expected_depth || !hashes.insert(frame.data().expansion_hash()) {
                return Err(malformed(
                    scope,
                    super::super::super::MacroExpansionEntity::ID,
                    format!("effect macro path for {effect:?} is noncontiguous or repeats a hash"),
                ));
            }
        }
        if let Some(first) = path.first() {
            expected_entries.insert((*effect.function(), first.clone()));
            expected_exits.insert((path.last().expect("nonempty path").clone(), *effect));
            expected_links.extend(
                path.windows(2)
                    .map(|pair| (pair[0].clone(), pair[1].clone())),
            );
        }
        topology.effect_macro_paths.insert(
            *effect,
            path.iter()
                .map(|key| {
                    entities
                        .effect_macros
                        .get(key)
                        .expect("indexed macro key")
                        .data()
                        .expansion_hash()
                })
                .collect(),
        );
    }

    let actual_entry_rows = load_relations::<FunctionEntersMacroExpansion>(scope, view)?;
    let actual_entry_count = actual_entry_rows.len();
    let mut entry_refs = BTreeMap::new();
    for relation in actual_entry_rows {
        let edge = (
            entities.functions.key_for_id(
                scope,
                relation.from,
                FunctionEntersMacroExpansion::ID,
                "from",
            )?,
            entities.effect_macros.key_for_id(
                scope,
                relation.to,
                FunctionEntersMacroExpansion::ID,
                "to",
            )?,
        );
        if entry_refs
            .insert(
                edge.clone(),
                ScopedRelationRef::new(scope.clone(), relation.relation),
            )
            .is_some()
        {
            return Err(malformed(
                scope,
                FunctionEntersMacroExpansion::ID,
                format!("duplicate effect macro entry edge {edge:?}"),
            ));
        }
    }
    let actual_entries = entry_refs.keys().cloned().collect::<BTreeSet<_>>();
    let actual_link_rows = load_relations::<MacroExpansionEntersMacroExpansion>(scope, view)?;
    let actual_link_count = actual_link_rows.len();
    let mut link_refs = BTreeMap::new();
    for relation in actual_link_rows {
        let edge = (
            entities.effect_macros.key_for_id(
                scope,
                relation.from,
                MacroExpansionEntersMacroExpansion::ID,
                "from",
            )?,
            entities.effect_macros.key_for_id(
                scope,
                relation.to,
                MacroExpansionEntersMacroExpansion::ID,
                "to",
            )?,
        );
        if link_refs
            .insert(
                edge.clone(),
                ScopedRelationRef::new(scope.clone(), relation.relation),
            )
            .is_some()
        {
            return Err(malformed(
                scope,
                MacroExpansionEntersMacroExpansion::ID,
                format!("duplicate effect macro link edge {edge:?}"),
            ));
        }
    }
    let actual_links = link_refs.keys().cloned().collect::<BTreeSet<_>>();
    let actual_exit_rows = load_relations::<MacroExpansionProducesEffectSite>(scope, view)?;
    let actual_exit_count = actual_exit_rows.len();
    let mut exit_refs = BTreeMap::new();
    for relation in actual_exit_rows {
        let edge = (
            entities.effect_macros.key_for_id(
                scope,
                relation.from,
                MacroExpansionProducesEffectSite::ID,
                "from",
            )?,
            entities.effects.key_for_id(
                scope,
                relation.to,
                MacroExpansionProducesEffectSite::ID,
                "to",
            )?,
        );
        if exit_refs
            .insert(
                edge.clone(),
                ScopedRelationRef::new(scope.clone(), relation.relation),
            )
            .is_some()
        {
            return Err(malformed(
                scope,
                MacroExpansionProducesEffectSite::ID,
                format!("duplicate effect macro exit edge {edge:?}"),
            ));
        }
    }
    let actual_exits = exit_refs.keys().cloned().collect::<BTreeSet<_>>();
    require_expected_edges(
        scope,
        FunctionEntersMacroExpansion::ID,
        &actual_entries,
        &expected_entries,
        actual_entry_count,
    )?;
    require_expected_edges(
        scope,
        MacroExpansionEntersMacroExpansion::ID,
        &actual_links,
        &expected_links,
        actual_link_count,
    )?;
    require_expected_edges(
        scope,
        MacroExpansionProducesEffectSite::ID,
        &actual_exits,
        &expected_exits,
        actual_exit_count,
    )?;
    let macro_callsites = index_effect_macro_callsites(scope, view, entities)?;
    for (effect, path) in frames {
        let Some(first) = path.first() else {
            continue;
        };
        let entry = entry_refs
            .get(&(*effect.function(), first.clone()))
            .expect("validated effect macro entry is present")
            .clone();
        let links = path
            .windows(2)
            .map(|pair| {
                link_refs
                    .get(&(pair[0].clone(), pair[1].clone()))
                    .expect("validated effect macro link is present")
                    .clone()
            })
            .collect();
        let exit = exit_refs
            .get(&(
                path.last().expect("nonempty effect macro path").clone(),
                effect,
            ))
            .expect("validated effect macro exit is present")
            .clone();
        let frame_entities = path
            .iter()
            .map(|key| {
                entities
                    .effect_macros
                    .get(key)
                    .expect("macro key came from the entity table")
                    .clone()
            })
            .collect();
        let callsites = path
            .iter()
            .map(|key| macro_callsites.get(key).cloned())
            .collect();
        topology.indexed_effect_macro_paths.insert(
            effect,
            super::IndexedEffectMacroPath::new(frame_entities, entry, links, exit, callsites),
        );
    }
    Ok(())
}

fn index_effect_macro_callsites(
    scope: &ArtifactScopeId,
    view: ArtifactDbView<'_>,
    entities: &ArtifactProgramIndex,
) -> Result<
    BTreeMap<MacroExpansionKey, super::IndexedEffectMacroCallsite>,
    WorkspaceProgramIndexError,
> {
    let mut callsites = BTreeMap::new();
    for relation in load_relations::<MacroExpansionHasCallsite>(scope, view)? {
        let frame = entities.effect_macros.key_for_id(
            scope,
            relation.from,
            MacroExpansionHasCallsite::ID,
            "from",
        )?;
        let anchor = entities.source_anchors.entity_for_id(
            scope,
            relation.to,
            MacroExpansionHasCallsite::ID,
            "to",
        )?;
        let callsite = super::IndexedEffectMacroCallsite::new(
            anchor.data().anchor().clone(),
            anchor.id(),
            ScopedRelationRef::new(scope.clone(), relation.relation),
        );
        if callsites.insert(frame.clone(), callsite).is_some() {
            return Err(malformed(
                scope,
                MacroExpansionHasCallsite::ID,
                format!("effect macro frame {frame:?} has multiple invocation anchors"),
            ));
        }
    }
    Ok(callsites)
}

pub(super) fn validate_callsite_cardinality<R>(
    scope: &ArtifactScopeId,
    view: ArtifactDbView<'_>,
    frames: &EntityTable<R::From>,
    anchors: &EntityTable<R::To>,
) -> Result<(), WorkspaceProgramIndexError>
where
    R: super::super::super::super::schema::RelationSchema,
    R::From: super::super::super::super::schema::EntitySchema,
    R::To: super::super::super::super::schema::EntitySchema,
{
    let mut seen = BTreeSet::new();
    for relation in load_relations::<R>(scope, view)? {
        let frame = frames.key_for_id(scope, relation.from, R::ID, "from")?;
        anchors.entity_for_id(scope, relation.to, R::ID, "to")?;
        if !seen.insert(frame) {
            return Err(malformed(
                scope,
                R::ID,
                "one macro frame has multiple invocation anchors",
            ));
        }
    }
    Ok(())
}

const fn effect_source_role_order(role: EffectSourceAnchorRole) -> u8 {
    match role {
        EffectSourceAnchorRole::Presentation => 0,
        EffectSourceAnchorRole::Expanded => 1,
    }
}

pub(super) fn require_expected_edges<T: Ord + std::fmt::Debug>(
    scope: &ArtifactScopeId,
    schema: &'static str,
    actual: &BTreeSet<T>,
    expected: &BTreeSet<T>,
    actual_row_count: usize,
) -> Result<(), WorkspaceProgramIndexError> {
    if actual.len() != actual_row_count {
        Err(malformed(
            scope,
            schema,
            "macro path contains duplicate semantic relations",
        ))
    } else if actual == expected {
        Ok(())
    } else {
        Err(malformed(
            scope,
            schema,
            format!("macro path edges differ: expected {expected:?}, found {actual:?}"),
        ))
    }
}
