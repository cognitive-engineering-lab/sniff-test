//! Marker occurrence, claim ownership, and typed candidate validation.

use std::collections::{BTreeMap, BTreeSet};

use super::super::super::super::human::EvidenceClaimSelector;
use super::super::super::super::human::markers::{
    CallOccurrenceHasMarkerClaimCandidate, EffectSiteHasMarkerClaimCandidate,
    FunctionHasMarkerClaimCandidate, MarkerClaimEntity, MarkerClaimKey, MarkerOccurrenceEntity,
    MarkerOccurrenceHasClaim, MarkerOccurrenceHasSourceAnchor, MarkerOccurrenceKey,
    UnsafeOperationHasMarkerClaimCandidate,
};
use super::super::super::super::safety::operations::UnsafeOperationKey;
use super::super::super::super::schema::RowSchema;
use super::super::super::super::view::ArtifactDbView;
use super::super::super::super::workspace::{ArtifactScopeId, ScopedRelationRef};
use super::super::super::{EffectSiteKey, topology::CallOccurrenceKey};
use super::super::index::{
    ArtifactProgramIndex, WorkspaceProgramIndexError, load_relations, malformed,
};
use super::ArtifactTopology;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum MarkerCandidateEndpoint {
    Call(CallOccurrenceKey),
    Effect(EffectSiteKey),
    Unsafe(UnsafeOperationKey),
}

#[derive(Default)]
struct MarkerPathPrefixCache {
    matches: BTreeMap<(MarkerOccurrenceKey, MarkerCandidateEndpoint), bool>,
    #[cfg(test)]
    path_comparisons: usize,
}

impl MarkerPathPrefixCache {
    fn matches(
        &mut self,
        occurrence: &MarkerOccurrenceKey,
        endpoint: MarkerCandidateEndpoint,
        marker_path: &[crate::namespace::StableExpansionHash],
        endpoint_path: &[crate::namespace::StableExpansionHash],
    ) -> bool {
        let key = (occurrence.clone(), endpoint);
        if let Some(result) = self.matches.get(&key) {
            return *result;
        }
        #[cfg(test)]
        {
            self.path_comparisons += 1;
        }
        let result = endpoint_path.starts_with(marker_path);
        self.matches.insert(key, result);
        result
    }
}

pub(super) fn validate(
    scope: &ArtifactScopeId,
    view: ArtifactDbView<'_>,
    entities: &ArtifactProgramIndex,
    topology: &mut ArtifactTopology,
) -> Result<(), WorkspaceProgramIndexError> {
    validate_occurrences(scope, view, entities)?;
    validate_claims(scope, view, entities)?;
    validate_function_candidates(scope, view, entities, topology)?;
    let mut path_cache = MarkerPathPrefixCache::default();
    validate_call_candidates(scope, view, entities, topology, &mut path_cache)?;
    validate_effect_candidates(scope, view, entities, topology, &mut path_cache)?;
    validate_unsafe_candidates(scope, view, entities, topology, &mut path_cache)?;
    for candidates in topology.function_marker_candidates.values_mut() {
        candidates.sort();
    }
    for candidates in topology.call_marker_candidates.values_mut() {
        candidates.sort();
    }
    for candidates in topology.effect_marker_candidates.values_mut() {
        candidates.sort();
    }
    for candidates in topology.unsafe_marker_candidates.values_mut() {
        candidates.sort();
    }
    Ok(())
}

fn validate_occurrences(
    scope: &ArtifactScopeId,
    view: ArtifactDbView<'_>,
    entities: &ArtifactProgramIndex,
) -> Result<(), WorkspaceProgramIndexError> {
    for occurrence in entities.marker_occurrences.by_key.values() {
        let key = occurrence.data().key();
        let path = occurrence.data().expansion_path();
        let shape_is_valid = match key.origin() {
            None => path.is_empty(),
            Some(origin) => path.last() == Some(&origin),
        };
        if !shape_is_valid || path.iter().collect::<BTreeSet<_>>().len() != path.len() {
            return Err(malformed(
                scope,
                MarkerOccurrenceEntity::ID,
                format!("marker occurrence {key:?} has an invalid expansion path"),
            ));
        }
    }

    let mut anchors = BTreeMap::<MarkerOccurrenceKey, super::super::super::SourceAnchorKey>::new();
    for relation in load_relations::<MarkerOccurrenceHasSourceAnchor>(scope, view)? {
        let occurrence = entities.marker_occurrences.key_for_id(
            scope,
            relation.from,
            MarkerOccurrenceHasSourceAnchor::ID,
            "from",
        )?;
        let anchor = entities.source_anchors.key_for_id(
            scope,
            relation.to,
            MarkerOccurrenceHasSourceAnchor::ID,
            "to",
        )?;
        if occurrence.anchor() != &anchor || anchors.insert(occurrence.clone(), anchor).is_some() {
            return Err(malformed(
                scope,
                MarkerOccurrenceHasSourceAnchor::ID,
                format!("marker occurrence {occurrence:?} has invalid physical anchoring"),
            ));
        }
    }
    for occurrence in entities.marker_occurrences.by_key.keys() {
        if !anchors.contains_key(occurrence) {
            return Err(malformed(
                scope,
                MarkerOccurrenceHasSourceAnchor::ID,
                format!("marker occurrence {occurrence:?} has no physical anchor"),
            ));
        }
    }
    Ok(())
}

fn validate_claims(
    scope: &ArtifactScopeId,
    view: ArtifactDbView<'_>,
    entities: &ArtifactProgramIndex,
) -> Result<(), WorkspaceProgramIndexError> {
    let mut owners = BTreeMap::<MarkerClaimKey, MarkerOccurrenceKey>::new();
    for relation in load_relations::<MarkerOccurrenceHasClaim>(scope, view)? {
        let occurrence = entities.marker_occurrences.key_for_id(
            scope,
            relation.from,
            MarkerOccurrenceHasClaim::ID,
            "from",
        )?;
        let claim = entities.marker_claims.key_for_id(
            scope,
            relation.to,
            MarkerOccurrenceHasClaim::ID,
            "to",
        )?;
        if claim.occurrence() != &occurrence || owners.insert(claim.clone(), occurrence).is_some() {
            return Err(malformed(
                scope,
                MarkerOccurrenceHasClaim::ID,
                format!("marker claim {claim:?} has invalid occurrence ownership"),
            ));
        }
    }

    let mut ordinals = BTreeMap::new();
    for claim in entities.marker_claims.by_key.values() {
        let key = claim.data().key();
        if !owners.contains_key(key) {
            return Err(malformed(
                scope,
                MarkerOccurrenceHasClaim::ID,
                format!("marker claim {key:?} has no owning occurrence"),
            ));
        }
        if claim.data().rationale().trim().is_empty() || !valid_selector(claim.data().selector()) {
            return Err(malformed(
                scope,
                MarkerClaimEntity::ID,
                format!("marker claim {key:?} has invalid human evidence"),
            ));
        }
        ordinals
            .entry((key.occurrence().clone(), key.domain().clone()))
            .or_insert_with(Vec::new)
            .push(key.source_ordinal());
    }
    for ((occurrence, domain), values) in &mut ordinals {
        values.sort_unstable();
        if !(0_u32..)
            .zip(values.iter().copied())
            .all(|(expected, actual)| expected == actual)
        {
            return Err(malformed(
                scope,
                MarkerClaimEntity::ID,
                format!(
                    "marker claims for {occurrence:?} in {domain:?} have noncontiguous ordinals"
                ),
            ));
        }
    }
    Ok(())
}

fn valid_selector(selector: &EvidenceClaimSelector) -> bool {
    match selector {
        EvidenceClaimSelector::Unnamed => true,
        EvidenceClaimSelector::Named(name) => !name.trim().is_empty(),
        EvidenceClaimSelector::Explicit(references) => {
            !references.is_empty()
                && references
                    .iter()
                    .all(|reference| !reference.trim().is_empty())
                && references.iter().collect::<BTreeSet<_>>().len() == references.len()
        }
    }
}

fn validate_function_candidates(
    scope: &ArtifactScopeId,
    view: ArtifactDbView<'_>,
    entities: &ArtifactProgramIndex,
    topology: &mut ArtifactTopology,
) -> Result<(), WorkspaceProgramIndexError> {
    let mut seen = BTreeMap::new();
    for relation in load_relations::<FunctionHasMarkerClaimCandidate>(scope, view)? {
        let endpoint = entities.functions.key_for_id(
            scope,
            relation.from,
            FunctionHasMarkerClaimCandidate::ID,
            "from",
        )?;
        let claim = entities.marker_claims.key_for_id(
            scope,
            relation.to,
            FunctionHasMarkerClaimCandidate::ID,
            "to",
        )?;
        require_unique_candidate(
            scope,
            FunctionHasMarkerClaimCandidate::ID,
            &mut seen,
            &endpoint,
            &claim,
            (
                relation.data.source_callsite(),
                relation.data.macro_definition_first(),
            ),
        )?;
        let claim_id = entities
            .marker_claims
            .get(&claim)
            .expect("candidate claim was resolved from the entity table")
            .id();
        topology
            .function_marker_candidates
            .entry(endpoint)
            .or_default()
            .push(super::IndexedMarkerCandidate::new(
                claim,
                claim_id,
                ScopedRelationRef::new(scope.clone(), relation.relation.clone()),
                relation.data.source_callsite(),
                relation.data.macro_definition_first(),
            ));
    }
    Ok(())
}

fn validate_call_candidates(
    scope: &ArtifactScopeId,
    view: ArtifactDbView<'_>,
    entities: &ArtifactProgramIndex,
    topology: &mut ArtifactTopology,
    path_cache: &mut MarkerPathPrefixCache,
) -> Result<(), WorkspaceProgramIndexError> {
    let mut seen = BTreeMap::new();
    for relation in load_relations::<CallOccurrenceHasMarkerClaimCandidate>(scope, view)? {
        let endpoint = entities.occurrences.key_for_id(
            scope,
            relation.from,
            CallOccurrenceHasMarkerClaimCandidate::ID,
            "from",
        )?;
        let claim = entities.marker_claims.key_for_id(
            scope,
            relation.to,
            CallOccurrenceHasMarkerClaimCandidate::ID,
            "to",
        )?;
        require_path_prefix(
            scope,
            CallOccurrenceHasMarkerClaimCandidate::ID,
            entities,
            &claim,
            MarkerCandidateEndpoint::Call(endpoint),
            topology
                .call_macro_paths
                .get(&endpoint)
                .map_or(&[], Vec::as_slice),
            path_cache,
        )?;
        require_unique_candidate(
            scope,
            CallOccurrenceHasMarkerClaimCandidate::ID,
            &mut seen,
            &endpoint,
            &claim,
            (
                relation.data.source_callsite(),
                relation.data.macro_definition_first(),
            ),
        )?;
        let claim_id = entities
            .marker_claims
            .get(&claim)
            .expect("candidate claim was resolved from the entity table")
            .id();
        topology
            .call_marker_candidates
            .entry(endpoint)
            .or_default()
            .push(super::IndexedMarkerCandidate::new(
                claim,
                claim_id,
                ScopedRelationRef::new(scope.clone(), relation.relation.clone()),
                relation.data.source_callsite(),
                relation.data.macro_definition_first(),
            ));
    }
    Ok(())
}

fn validate_effect_candidates(
    scope: &ArtifactScopeId,
    view: ArtifactDbView<'_>,
    entities: &ArtifactProgramIndex,
    topology: &mut ArtifactTopology,
    path_cache: &mut MarkerPathPrefixCache,
) -> Result<(), WorkspaceProgramIndexError> {
    let mut seen = BTreeMap::new();
    for relation in load_relations::<EffectSiteHasMarkerClaimCandidate>(scope, view)? {
        let endpoint = entities.effects.key_for_id(
            scope,
            relation.from,
            EffectSiteHasMarkerClaimCandidate::ID,
            "from",
        )?;
        let claim = entities.marker_claims.key_for_id(
            scope,
            relation.to,
            EffectSiteHasMarkerClaimCandidate::ID,
            "to",
        )?;
        require_path_prefix(
            scope,
            EffectSiteHasMarkerClaimCandidate::ID,
            entities,
            &claim,
            MarkerCandidateEndpoint::Effect(endpoint),
            topology
                .effect_macro_paths
                .get(&endpoint)
                .map_or(&[], Vec::as_slice),
            path_cache,
        )?;
        require_unique_candidate(
            scope,
            EffectSiteHasMarkerClaimCandidate::ID,
            &mut seen,
            &endpoint,
            &claim,
            (
                relation.data.source_callsite(),
                relation.data.macro_definition_first(),
            ),
        )?;
        let claim_id = entities
            .marker_claims
            .get(&claim)
            .expect("candidate claim was resolved from the entity table")
            .id();
        topology
            .effect_marker_candidates
            .entry(endpoint)
            .or_default()
            .push(super::IndexedMarkerCandidate::new(
                claim,
                claim_id,
                ScopedRelationRef::new(scope.clone(), relation.relation.clone()),
                relation.data.source_callsite(),
                relation.data.macro_definition_first(),
            ));
    }
    Ok(())
}

fn validate_unsafe_candidates(
    scope: &ArtifactScopeId,
    view: ArtifactDbView<'_>,
    entities: &ArtifactProgramIndex,
    topology: &mut ArtifactTopology,
    path_cache: &mut MarkerPathPrefixCache,
) -> Result<(), WorkspaceProgramIndexError> {
    let mut seen = BTreeMap::new();
    for relation in load_relations::<UnsafeOperationHasMarkerClaimCandidate>(scope, view)? {
        let endpoint = entities.unsafe_operations.key_for_id(
            scope,
            relation.from,
            UnsafeOperationHasMarkerClaimCandidate::ID,
            "from",
        )?;
        let claim = entities.marker_claims.key_for_id(
            scope,
            relation.to,
            UnsafeOperationHasMarkerClaimCandidate::ID,
            "to",
        )?;
        require_path_prefix(
            scope,
            UnsafeOperationHasMarkerClaimCandidate::ID,
            entities,
            &claim,
            MarkerCandidateEndpoint::Unsafe(endpoint),
            topology
                .unsafe_macro_paths
                .get(&endpoint)
                .map_or(&[], Vec::as_slice),
            path_cache,
        )?;
        require_unique_candidate(
            scope,
            UnsafeOperationHasMarkerClaimCandidate::ID,
            &mut seen,
            &endpoint,
            &claim,
            (
                relation.data.source_callsite(),
                relation.data.macro_definition_first(),
            ),
        )?;
        let claim_id = entities
            .marker_claims
            .get(&claim)
            .expect("candidate claim was resolved from the entity table")
            .id();
        topology
            .unsafe_marker_candidates
            .entry(endpoint)
            .or_default()
            .push(super::IndexedMarkerCandidate::new(
                claim,
                claim_id,
                ScopedRelationRef::new(scope.clone(), relation.relation.clone()),
                relation.data.source_callsite(),
                relation.data.macro_definition_first(),
            ));
    }
    Ok(())
}

fn require_path_prefix(
    scope: &ArtifactScopeId,
    schema: &'static str,
    entities: &ArtifactProgramIndex,
    claim: &MarkerClaimKey,
    endpoint: MarkerCandidateEndpoint,
    endpoint_path: &[crate::namespace::StableExpansionHash],
    path_cache: &mut MarkerPathPrefixCache,
) -> Result<(), WorkspaceProgramIndexError> {
    let occurrence = entities
        .marker_occurrences
        .get(claim.occurrence())
        .expect("claim ownership validation resolved its occurrence");
    if path_cache.matches(
        claim.occurrence(),
        endpoint,
        occurrence.data().expansion_path(),
        endpoint_path,
    ) {
        Ok(())
    } else {
        Err(malformed(
            scope,
            schema,
            format!(
                "marker claim {claim:?} with expansion path {:?} is not on the candidate endpoint's macro path {endpoint_path:?}",
                occurrence.data().expansion_path(),
            ),
        ))
    }
}

fn require_unique_candidate<K: Clone + Ord + std::fmt::Debug>(
    scope: &ArtifactScopeId,
    schema: &'static str,
    seen: &mut BTreeMap<(K, MarkerClaimKey), (bool, bool)>,
    endpoint: &K,
    claim: &MarkerClaimKey,
    flags: (bool, bool),
) -> Result<(), WorkspaceProgramIndexError> {
    if !flags.0 && !flags.1 {
        return Err(malformed(
            scope,
            schema,
            format!("candidate endpoint {endpoint:?} has no enabled marker probing mode"),
        ));
    }
    if seen
        .insert((endpoint.clone(), claim.clone()), flags)
        .is_none()
    {
        Ok(())
    } else {
        Err(malformed(
            scope,
            schema,
            format!("candidate endpoint {endpoint:?} repeats marker claim {claim:?}"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{MarkerCandidateEndpoint, MarkerPathPrefixCache};
    use crate::analysis::facts::human::markers::MarkerOccurrenceKey;
    use crate::analysis::facts::program::topology::CallOccurrenceKey;
    use crate::analysis::facts::program::{FunctionKey, SourceAnchorKey};
    use crate::namespace::{StableDefPathHash, StableExpansionHash};

    fn definition(value: u128) -> StableDefPathHash {
        serde_json::from_str(&format!("\"{value:032x}\"")).unwrap()
    }

    fn expansion(value: u128) -> StableExpansionHash {
        serde_json::from_str(&format!("\"{value:032x}\"")).unwrap()
    }

    #[test]
    fn repeated_claims_compare_one_marker_endpoint_path_once() {
        let marker_path = (1..=64).map(expansion).collect::<Vec<_>>();
        let mut endpoint_path = marker_path.clone();
        endpoint_path.push(expansion(65));
        let occurrence = MarkerOccurrenceKey::new(
            SourceAnchorKey::new("src/lib.rs", 0, 1),
            marker_path.last().copied(),
        );
        let endpoint = MarkerCandidateEndpoint::Call(CallOccurrenceKey::new(
            FunctionKey::new(definition(1), None),
            0,
        ));
        let mut cache = MarkerPathPrefixCache::default();

        for _ in 0..10_000 {
            assert!(cache.matches(&occurrence, endpoint.clone(), &marker_path, &endpoint_path,));
        }
        assert_eq!(cache.path_comparisons, 1);
        assert_eq!(cache.matches.len(), 1);
    }
}
