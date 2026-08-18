//! Permanent source-marker identities and typed attachment candidates.

use serde::{Deserialize, Serialize};

use super::super::evaluation::DomainId;
use super::super::pack::{AnalysisPack, AnalysisRegistry, PackRegistrationError};
use super::super::pass::{ArtifactPass, PassDescriptor, PassError, PassInput, PassOutput};
use super::super::program::topology::CallOccurrenceEntity;
use super::super::program::{
    EffectSiteEntity, FunctionEntity, SourceAnchorEntity, SourceAnchorKey,
};
use super::super::safety::operations::UnsafeOperationEntity;
use super::super::schema::{
    EntityHandle, EntitySchema, PassId, RelationSchema, RowSchema, SchemaId,
};
use super::EvidenceClaimSelector;
use crate::analysis::collected::{CollectedArtifact, CollectedMarkerOccurrence};
use crate::namespace::StableExpansionHash;

/// Stable identity of one physical marker block in one expansion instance.
///
/// Source-authored markers have no origin. A marker parsed from a macro
/// definition carries the stable hash of the exact expansion that instantiated
/// that physical comment block.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct MarkerOccurrenceKey {
    anchor: SourceAnchorKey,
    origin: Option<StableExpansionHash>,
}

impl MarkerOccurrenceKey {
    #[must_use]
    pub(crate) const fn new(anchor: SourceAnchorKey, origin: Option<StableExpansionHash>) -> Self {
        Self { anchor, origin }
    }

    #[must_use]
    pub(crate) const fn anchor(&self) -> &SourceAnchorKey {
        &self.anchor
    }

    #[must_use]
    pub(crate) const fn origin(&self) -> Option<StableExpansionHash> {
        self.origin
    }
}

/// One logical source-marker occurrence with its outer-to-origin macro path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct MarkerOccurrenceEntity {
    key: MarkerOccurrenceKey,
    expansion_path: Vec<StableExpansionHash>,
}

impl RowSchema for MarkerOccurrenceEntity {
    const ID: &'static str = "sniff-test.human.marker-occurrence";
    const VERSION: u32 = 1;
}

impl EntitySchema for MarkerOccurrenceEntity {
    type Key = MarkerOccurrenceKey;

    fn key(&self) -> Self::Key {
        self.key.clone()
    }
}

impl MarkerOccurrenceEntity {
    #[must_use]
    pub(crate) const fn new(
        key: MarkerOccurrenceKey,
        expansion_path: Vec<StableExpansionHash>,
    ) -> Self {
        Self {
            key,
            expansion_path,
        }
    }

    #[must_use]
    pub(crate) const fn key(&self) -> &MarkerOccurrenceKey {
        &self.key
    }

    #[must_use]
    pub(crate) fn expansion_path(&self) -> &[StableExpansionHash] {
        &self.expansion_path
    }
}

/// Stable identity of one source-ordered claim within a marker occurrence.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct MarkerClaimKey {
    occurrence: MarkerOccurrenceKey,
    domain: DomainId,
    source_ordinal: u32,
}

impl MarkerClaimKey {
    #[must_use]
    pub(crate) const fn new(
        occurrence: MarkerOccurrenceKey,
        domain: DomainId,
        source_ordinal: u32,
    ) -> Self {
        Self {
            occurrence,
            domain,
            source_ordinal,
        }
    }

    #[must_use]
    pub(crate) const fn occurrence(&self) -> &MarkerOccurrenceKey {
        &self.occurrence
    }

    #[must_use]
    pub(crate) const fn domain(&self) -> &DomainId {
        &self.domain
    }

    #[must_use]
    pub(crate) const fn source_ordinal(&self) -> u32 {
        self.source_ordinal
    }
}

/// One raw human claim attached to an exact logical marker occurrence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct MarkerClaimEntity {
    key: MarkerClaimKey,
    selector: EvidenceClaimSelector,
    rationale: String,
}

impl RowSchema for MarkerClaimEntity {
    const ID: &'static str = "sniff-test.human.marker-claim";
    const VERSION: u32 = 1;
}

impl EntitySchema for MarkerClaimEntity {
    type Key = MarkerClaimKey;

    fn key(&self) -> Self::Key {
        self.key.clone()
    }
}

impl MarkerClaimEntity {
    #[must_use]
    pub(crate) fn new(
        key: MarkerClaimKey,
        selector: EvidenceClaimSelector,
        rationale: impl Into<String>,
    ) -> Self {
        Self {
            key,
            selector,
            rationale: rationale.into(),
        }
    }

    #[must_use]
    pub(crate) const fn key(&self) -> &MarkerClaimKey {
        &self.key
    }

    #[must_use]
    pub(crate) const fn selector(&self) -> &EvidenceClaimSelector {
        &self.selector
    }

    #[must_use]
    pub(crate) fn rationale(&self) -> &str {
        &self.rationale
    }
}

macro_rules! empty_relation {
    ($(#[$meta:meta])* $name:ident, $id:literal, $from:ty, $to:ty) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
        #[serde(rename_all = "kebab-case", deny_unknown_fields)]
        pub(crate) struct $name {}

        impl RowSchema for $name {
            const ID: &'static str = $id;
            const VERSION: u32 = 1;
        }

        impl RelationSchema for $name {
            type From = $from;
            type To = $to;
        }

        impl $name {
            #[must_use]
            pub(crate) const fn new() -> Self {
                Self {}
            }
        }
    };
}

empty_relation!(
    /// Connects a logical marker occurrence to its verified physical anchor.
    MarkerOccurrenceHasSourceAnchor,
    "sniff-test.human.marker-occurrence-has-source-anchor",
    MarkerOccurrenceEntity,
    SourceAnchorEntity
);
empty_relation!(
    /// Connects a logical marker occurrence to one source-ordered claim.
    MarkerOccurrenceHasClaim,
    "sniff-test.human.marker-occurrence-has-claim",
    MarkerOccurrenceEntity,
    MarkerClaimEntity
);

macro_rules! candidate_relation {
    ($(#[$meta:meta])* $name:ident, $id:literal, $from:ty) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
        #[serde(rename_all = "kebab-case", deny_unknown_fields)]
        pub(crate) struct $name {
            source_callsite: bool,
            macro_definition_first: bool,
        }

        impl RowSchema for $name {
            const ID: &'static str = $id;
            const VERSION: u32 = 1;
        }

        impl RelationSchema for $name {
            type From = $from;
            type To = MarkerClaimEntity;
        }

        impl $name {
            #[must_use]
            pub(crate) const fn new(
                source_callsite: bool,
                macro_definition_first: bool,
            ) -> Self {
                Self {
                    source_callsite,
                    macro_definition_first,
                }
            }

            #[must_use]
            pub(crate) const fn source_callsite(self) -> bool {
                self.source_callsite
            }

            #[must_use]
            pub(crate) const fn macro_definition_first(self) -> bool {
                self.macro_definition_first
            }
        }
    };
}

candidate_relation!(
    /// A function is a lexical attachment candidate for one marker claim.
    FunctionHasMarkerClaimCandidate,
    "sniff-test.human.function-has-marker-claim-candidate",
    FunctionEntity
);
candidate_relation!(
    /// A call occurrence is a lexical attachment candidate for one marker claim.
    CallOccurrenceHasMarkerClaimCandidate,
    "sniff-test.human.call-occurrence-has-marker-claim-candidate",
    CallOccurrenceEntity
);
candidate_relation!(
    /// An exact MIR effect is a lexical attachment candidate for one marker claim.
    EffectSiteHasMarkerClaimCandidate,
    "sniff-test.human.effect-site-has-marker-claim-candidate",
    EffectSiteEntity
);
candidate_relation!(
    /// A THIR unsafe operation is a lexical attachment candidate for one marker claim.
    UnsafeOperationHasMarkerClaimCandidate,
    "sniff-test.human.unsafe-operation-has-marker-claim-candidate",
    UnsafeOperationEntity
);

/// Schema-only human-marker pack.
///
/// Core program and safety schemas must be installed first because candidate
/// relations use their typed entities as endpoints.
pub(crate) struct HumanMarkerPack;

impl<C: ?Sized> AnalysisPack<C> for HumanMarkerPack {
    fn register(&self, registry: &mut AnalysisRegistry<C>) -> Result<(), PackRegistrationError> {
        registry.register_entity::<MarkerOccurrenceEntity>()?;
        registry.register_entity::<MarkerClaimEntity>()?;
        registry.register_relation::<MarkerOccurrenceHasSourceAnchor>()?;
        registry.register_relation::<MarkerOccurrenceHasClaim>()?;
        registry.register_relation::<FunctionHasMarkerClaimCandidate>()?;
        registry.register_relation::<CallOccurrenceHasMarkerClaimCandidate>()?;
        registry.register_relation::<EffectSiteHasMarkerClaimCandidate>()?;
        registry.register_relation::<UnsafeOperationHasMarkerClaimCandidate>()?;
        Ok(())
    }
}

const COLLECT_HUMAN_MARKERS_PASS: &str = "sniff-test.human.collect-markers";

/// Composition pack for the sole permanent human-marker artifact producer.
pub(crate) struct HumanMarkerCollectionPack;

impl AnalysisPack<CollectedArtifact> for HumanMarkerCollectionPack {
    fn register(
        &self,
        registry: &mut AnalysisRegistry<CollectedArtifact>,
    ) -> Result<(), PackRegistrationError> {
        HumanMarkerPack.register(registry)?;
        registry.register_artifact_pass(CollectHumanMarkers)
    }
}

struct CollectHumanMarkers;

impl ArtifactPass<CollectedArtifact> for CollectHumanMarkers {
    fn descriptor(&self) -> PassDescriptor {
        PassDescriptor::new(PassId::new(COLLECT_HUMAN_MARKERS_PASS).unwrap())
            .with_reads([
                schema::<FunctionEntity>(),
                schema::<CallOccurrenceEntity>(),
                schema::<EffectSiteEntity>(),
                schema::<UnsafeOperationEntity>(),
                schema::<SourceAnchorEntity>(),
            ])
            .with_writes(marker_schema_ids())
    }

    fn run(
        &mut self,
        cx: &CollectedArtifact,
        _input: PassInput<'_>,
        output: &mut PassOutput<'_>,
    ) -> Result<(), PassError> {
        for occurrence in cx.marker_occurrences() {
            emit_marker_occurrence(occurrence, output)?;
        }
        Ok(())
    }
}

fn schema<S: RowSchema>() -> SchemaId {
    SchemaId::new(S::ID).expect("built-in human-marker schema IDs are valid")
}

fn marker_schema_ids() -> Vec<SchemaId> {
    vec![
        schema::<MarkerOccurrenceEntity>(),
        schema::<MarkerClaimEntity>(),
        schema::<MarkerOccurrenceHasSourceAnchor>(),
        schema::<MarkerOccurrenceHasClaim>(),
        schema::<FunctionHasMarkerClaimCandidate>(),
        schema::<CallOccurrenceHasMarkerClaimCandidate>(),
        schema::<EffectSiteHasMarkerClaimCandidate>(),
        schema::<UnsafeOperationHasMarkerClaimCandidate>(),
    ]
}

fn emit_marker_occurrence(
    occurrence: &CollectedMarkerOccurrence,
    output: &mut PassOutput<'_>,
) -> Result<(), PassError> {
    let occurrence_handle = output.insert_entity(occurrence.entity())?;
    output.relate(
        &occurrence_handle,
        &EntityHandle::<SourceAnchorEntity>::new(occurrence.entity().key().anchor().clone()),
        &MarkerOccurrenceHasSourceAnchor::new(),
    )?;

    for claim in occurrence.claims() {
        let claim_handle = output.insert_entity(claim)?;
        output.relate(
            &occurrence_handle,
            &claim_handle,
            &MarkerOccurrenceHasClaim::new(),
        )?;
    }
    for candidate in occurrence.function_candidates() {
        output.relate(
            &EntityHandle::<FunctionEntity>::new(*candidate.function()),
            &EntityHandle::<MarkerClaimEntity>::new(candidate.claim().clone()),
            candidate.relation(),
        )?;
    }
    for candidate in occurrence.call_candidates() {
        output.relate(
            &EntityHandle::<CallOccurrenceEntity>::new(*candidate.occurrence()),
            &EntityHandle::<MarkerClaimEntity>::new(candidate.claim().clone()),
            candidate.relation(),
        )?;
    }
    for candidate in occurrence.effect_candidates() {
        output.relate(
            &EntityHandle::<EffectSiteEntity>::new(*candidate.effect_site()),
            &EntityHandle::<MarkerClaimEntity>::new(candidate.claim().clone()),
            candidate.relation(),
        )?;
    }
    for candidate in occurrence.unsafe_operation_candidates() {
        output.relate(
            &EntityHandle::<UnsafeOperationEntity>::new(*candidate.unsafe_operation()),
            &EntityHandle::<MarkerClaimEntity>::new(candidate.claim().clone()),
            candidate.relation(),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        CallOccurrenceHasMarkerClaimCandidate, EffectSiteHasMarkerClaimCandidate,
        FunctionHasMarkerClaimCandidate, HumanMarkerPack, MarkerClaimEntity, MarkerClaimKey,
        MarkerOccurrenceEntity, MarkerOccurrenceHasClaim, MarkerOccurrenceHasSourceAnchor,
        MarkerOccurrenceKey, UnsafeOperationHasMarkerClaimCandidate,
    };
    use crate::analysis::facts::encoded::TableKind;
    use crate::analysis::facts::evaluation::DomainId;
    use crate::analysis::facts::human::EvidenceClaimSelector;
    use crate::analysis::facts::pack::AnalysisRegistry;
    use crate::analysis::facts::program::{CoreProgramPack, SourceAnchorKey};
    use crate::analysis::facts::safety::SafetyPack;
    use crate::analysis::facts::schema::{RelationSchema, RowSchema};
    use crate::namespace::StableExpansionHash;

    fn expansion(value: u128) -> StableExpansionHash {
        serde_json::from_str(&format!("\"{value:032x}\"")).expect("valid stable expansion hash")
    }

    fn anchor(start: u64, end: u64) -> SourceAnchorKey {
        SourceAnchorKey::new("src/lib.rs", start, end)
    }

    fn occurrence(
        source: SourceAnchorKey,
        origin: Option<StableExpansionHash>,
        expansion_path: Vec<StableExpansionHash>,
    ) -> MarkerOccurrenceEntity {
        MarkerOccurrenceEntity::new(MarkerOccurrenceKey::new(source, origin), expansion_path)
    }

    #[test]
    fn occurrence_and_claim_keys_preserve_physical_origin_domain_and_source_order() {
        let physical = anchor(10, 20);
        let source = occurrence(physical.clone(), None, Vec::new());
        let first_expansion = occurrence(
            physical.clone(),
            Some(expansion(2)),
            vec![expansion(1), expansion(2)],
        );
        let second_expansion = occurrence(
            physical,
            Some(expansion(3)),
            vec![expansion(1), expansion(3)],
        );

        assert_ne!(source.key(), first_expansion.key());
        assert_ne!(first_expansion.key(), second_expansion.key());
        assert!(source.expansion_path().is_empty());
        assert_eq!(
            first_expansion.expansion_path(),
            &[expansion(1), expansion(2)]
        );

        let panic = DomainId::new("sniff-test.panic").unwrap();
        let safety = DomainId::new("sniff-test.safety").unwrap();
        let first = MarkerClaimKey::new(first_expansion.key().clone(), panic.clone(), 0);
        let repeated_text = MarkerClaimKey::new(first_expansion.key().clone(), panic, 1);
        let other_domain = MarkerClaimKey::new(first_expansion.key().clone(), safety, 0);
        assert_ne!(first, repeated_text);
        assert_ne!(first, other_domain);
    }

    #[test]
    fn claim_payload_is_typed_and_preserves_raw_rationale() {
        let occurrence = MarkerOccurrenceKey::new(anchor(10, 20), None);
        let claim = MarkerClaimEntity::new(
            MarkerClaimKey::new(occurrence, DomainId::new("sniff-test.safety").unwrap(), 7),
            EvidenceClaimSelector::Named(String::from("valid pointer")),
            "  justified by the caller  ",
        );

        assert_eq!(claim.key().source_ordinal(), 7);
        assert_eq!(
            claim.selector(),
            &EvidenceClaimSelector::Named(String::from("valid pointer"))
        );
        assert_eq!(claim.rationale(), "  justified by the caller  ");
    }

    #[test]
    fn each_candidate_relation_has_typed_endpoints_and_both_probing_flags() {
        fn assert_relation<R: RelationSchema>() {}

        assert_relation::<FunctionHasMarkerClaimCandidate>();
        assert_relation::<CallOccurrenceHasMarkerClaimCandidate>();
        assert_relation::<EffectSiteHasMarkerClaimCandidate>();
        assert_relation::<UnsafeOperationHasMarkerClaimCandidate>();

        for encoded in [
            serde_json::to_value(FunctionHasMarkerClaimCandidate::new(true, false)).unwrap(),
            serde_json::to_value(CallOccurrenceHasMarkerClaimCandidate::new(false, true)).unwrap(),
            serde_json::to_value(EffectSiteHasMarkerClaimCandidate::new(true, true)).unwrap(),
            serde_json::to_value(UnsafeOperationHasMarkerClaimCandidate::new(false, false))
                .unwrap(),
        ] {
            assert_eq!(
                encoded,
                json!({
                    "source-callsite": encoded["source-callsite"],
                    "macro-definition-first": encoded["macro-definition-first"]
                })
            );
        }

        let relation = FunctionHasMarkerClaimCandidate::new(true, false);
        assert!(relation.source_callsite());
        assert!(!relation.macro_definition_first());
    }

    #[test]
    fn marker_pack_registers_strict_v1_artifact_schemas() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CoreProgramPack).unwrap();
        registry.install(&SafetyPack).unwrap();
        registry.install(&HumanMarkerPack).unwrap();

        for (id, kind) in [
            (MarkerOccurrenceEntity::ID, TableKind::Entity),
            (MarkerClaimEntity::ID, TableKind::Entity),
            (MarkerOccurrenceHasSourceAnchor::ID, TableKind::Relation),
            (MarkerOccurrenceHasClaim::ID, TableKind::Relation),
            (FunctionHasMarkerClaimCandidate::ID, TableKind::Relation),
            (
                CallOccurrenceHasMarkerClaimCandidate::ID,
                TableKind::Relation,
            ),
            (EffectSiteHasMarkerClaimCandidate::ID, TableKind::Relation),
            (
                UnsafeOperationHasMarkerClaimCandidate::ID,
                TableKind::Relation,
            ),
        ] {
            let descriptor = registry
                .schemas()
                .descriptors()
                .find(|descriptor| descriptor.id().as_str() == id)
                .expect("marker schema is registered");
            assert_eq!(descriptor.version(), 1, "{id}");
            assert_eq!(descriptor.kind(), kind, "{id}");
        }

        let occurrence_endpoints = registry
            .schemas()
            .descriptor_for::<MarkerOccurrenceHasClaim>()
            .unwrap()
            .relation_endpoints()
            .unwrap();
        assert_eq!(
            occurrence_endpoints.from.as_str(),
            MarkerOccurrenceEntity::ID
        );
        assert_eq!(occurrence_endpoints.to.as_str(), MarkerClaimEntity::ID);

        let function_endpoints = registry
            .schemas()
            .descriptor_for::<FunctionHasMarkerClaimCandidate>()
            .unwrap()
            .relation_endpoints()
            .unwrap();
        assert_eq!(
            function_endpoints.to.as_str(),
            MarkerClaimEntity::ID,
            "candidate relations point from typed endpoints to exact claims"
        );
    }

    #[test]
    fn marker_rows_reject_unknown_fields() {
        let invalid_occurrence = json!({
            "key": {
                "anchor": {"file": "src/lib.rs", "byte-start": 10, "byte-end": 20},
                "origin": null
            },
            "expansion-path": [],
            "legacy-id": "removed"
        });
        assert!(serde_json::from_value::<MarkerOccurrenceEntity>(invalid_occurrence).is_err());

        let invalid_relation = json!({
            "source-callsite": true,
            "macro-definition-first": false,
            "target-kind": "function"
        });
        assert!(
            serde_json::from_value::<FunctionHasMarkerClaimCandidate>(invalid_relation).is_err()
        );
    }
}

#[cfg(test)]
mod collection_tests {
    use std::collections::BTreeSet;

    use reachability::MirBodyLocation;

    use super::{
        CallOccurrenceHasMarkerClaimCandidate, EffectSiteHasMarkerClaimCandidate,
        FunctionHasMarkerClaimCandidate, HumanMarkerCollectionPack, MarkerClaimEntity,
        MarkerClaimKey, MarkerOccurrenceEntity, MarkerOccurrenceHasClaim,
        MarkerOccurrenceHasSourceAnchor, MarkerOccurrenceKey,
        UnsafeOperationHasMarkerClaimCandidate,
    };
    use crate::analysis::collected::{
        CollectedArtifact, CollectedArtifactInput, CollectedCallOccurrence, CollectedCallSite,
        CollectedEffectMarkerCandidate, CollectedEffectSite, CollectedFunctionBody,
        CollectedFunctionMarkerCandidate, CollectedMarkerCallCandidate, CollectedMarkerOccurrence,
        CollectedProgram, CollectedUnsafeOperation, CollectedUnsafeOperationMarkerCandidate,
    };
    use crate::analysis::facts::builder::ArtifactDbBuilder;
    use crate::analysis::facts::evaluation::DomainId;
    use crate::analysis::facts::human::EvidenceClaimSelector;
    use crate::analysis::facts::pack::AnalysisRegistry;
    use crate::analysis::facts::program::collector::CoreProgramCollectionPack;
    use crate::analysis::facts::program::topology::{
        CallAttributionRole, CallKind, CallOccurrenceEntity, CallOccurrenceKey, CallSiteEntity,
        CallSiteKey, CallableEntity, SafetyEffectGroupEntity, SafetyEffectGroupKey,
    };
    use crate::analysis::facts::program::{
        EffectSiteEntity, EffectSiteKey, FunctionBodyProvenance, FunctionEntity, FunctionKey,
        SourceAnchorEntity, SourceAnchorKey, SourceFileEntity,
    };
    use crate::analysis::facts::safety::collector::SafetyCollectionPack;
    use crate::analysis::facts::safety::operations::{
        SafetyOperationKind, UnsafeOperationEntity, UnsafeOperationKey,
    };
    use crate::analysis::facts::schema::{RowSchema, SchemaId};
    use crate::analysis::facts::view::ArtifactDbView;
    use crate::namespace::StableDefPathHash;

    fn definition(value: u128) -> StableDefPathHash {
        serde_json::from_str(&format!("\"{value:032x}\"")).expect("valid stable definition hash")
    }

    fn function(value: u128) -> FunctionKey {
        FunctionKey::new(definition(value), None)
    }

    fn anchor(start: u64, end: u64) -> SourceAnchorKey {
        SourceAnchorKey::new("src/lib.rs", start, end)
    }

    fn marker(owner: FunctionKey, source_anchor: SourceAnchorKey) -> CollectedMarkerOccurrence {
        let call = CallOccurrenceKey::new(owner, 0);
        let effect = EffectSiteKey::from_mir(
            owner,
            MirBodyLocation {
                basic_block: 0,
                statement_index: 0,
            },
        )
        .unwrap();
        let operation = UnsafeOperationKey::new(owner, 0);
        let occurrence = MarkerOccurrenceKey::new(source_anchor, None);
        let claim = MarkerClaimEntity::new(
            MarkerClaimKey::new(
                occurrence.clone(),
                DomainId::new("sniff-test.safety").unwrap(),
                0,
            ),
            EvidenceClaimSelector::Unnamed,
            "validated rationale",
        );
        CollectedMarkerOccurrence::new(
            MarkerOccurrenceEntity::new(occurrence, Vec::new()),
            vec![claim.clone()],
            vec![CollectedFunctionMarkerCandidate::new(
                owner,
                claim.key().clone(),
                FunctionHasMarkerClaimCandidate::new(true, false),
            )],
            vec![CollectedMarkerCallCandidate::new(
                call,
                claim.key().clone(),
                CallOccurrenceHasMarkerClaimCandidate::new(false, true),
            )],
            vec![CollectedEffectMarkerCandidate::new(
                effect,
                claim.key().clone(),
                EffectSiteHasMarkerClaimCandidate::new(true, true),
            )],
            vec![CollectedUnsafeOperationMarkerCandidate::new(
                operation,
                claim.key().clone(),
                UnsafeOperationHasMarkerClaimCandidate::new(true, false),
            )],
        )
    }

    fn artifact(reverse: bool) -> CollectedArtifact {
        let owner = function(1);
        let group = SafetyEffectGroupKey::new(owner, 0);
        let call = CallOccurrenceKey::new(owner, 0);
        let effect = EffectSiteKey::from_mir(
            owner,
            MirBodyLocation {
                basic_block: 0,
                statement_index: 0,
            },
        )
        .unwrap();
        let call = CollectedCallOccurrence::new(
            CallOccurrenceEntity::new(
                call,
                CallKind::IndirectCall,
                vec![CallAttributionRole::CallSite],
                false,
                false,
                Some(String::from("opaque call")),
            ),
            Vec::new(),
            Vec::new(),
            vec![group],
            Vec::new(),
            Vec::new(),
        );
        let body = CollectedFunctionBody::new(
            FunctionEntity::new(
                owner,
                "crate::root",
                FunctionBodyProvenance::DefiningArtifact,
            ),
            None,
            vec![CollectedCallSite::new(
                CallSiteEntity::new(CallSiteKey::new(owner, 0)),
                vec![call],
            )],
            vec![SafetyEffectGroupEntity::new(group)],
            vec![CollectedEffectSite::new(
                EffectSiteEntity::new(effect),
                Vec::new(),
                Vec::new(),
            )],
        );
        let mut anchors = vec![
            SourceAnchorEntity::new(anchor(10, 15)),
            SourceAnchorEntity::new(anchor(20, 25)),
        ];
        let callable = CallableEntity::new(
            owner,
            "crate::root",
            true,
            false,
            true,
            false,
            vec![String::from("crate::root")],
        );
        let mut markers = vec![marker(owner, anchor(10, 15)), marker(owner, anchor(20, 25))];
        if reverse {
            anchors.reverse();
            markers.reverse();
        }
        let program = CollectedProgram::try_new(
            vec![SourceFileEntity::new(
                "src/lib.rs",
                "src/lib.rs",
                "verified-hash",
                100,
            )],
            anchors,
            vec![callable],
            vec![body],
        )
        .unwrap();
        CollectedArtifact::try_new(CollectedArtifactInput {
            program,
            unsafe_operations: vec![CollectedUnsafeOperation::new(
                UnsafeOperationEntity::new(operation(owner), SafetyOperationKind::DerefRawPointer),
                group,
                Vec::new(),
                Vec::new(),
            )],
            panic_contracts: Vec::new(),
            safety_contracts: Vec::new(),
            mir_asserts: Vec::new(),
            marker_occurrences: markers,
        })
        .unwrap()
    }

    fn operation(owner: FunctionKey) -> UnsafeOperationKey {
        UnsafeOperationKey::new(owner, 0)
    }

    fn empty_artifact() -> CollectedArtifact {
        CollectedArtifact::try_new(CollectedArtifactInput {
            program: CollectedProgram::try_new(Vec::new(), Vec::new(), Vec::new(), Vec::new())
                .unwrap(),
            unsafe_operations: Vec::new(),
            panic_contracts: Vec::new(),
            safety_contracts: Vec::new(),
            mir_asserts: Vec::new(),
            marker_occurrences: Vec::new(),
        })
        .unwrap()
    }

    fn collect(
        artifact: &CollectedArtifact,
    ) -> (
        AnalysisRegistry<CollectedArtifact>,
        crate::analysis::facts::encoded::ArtifactFactIr,
    ) {
        let mut registry = AnalysisRegistry::<CollectedArtifact>::new();
        registry.install(&CoreProgramCollectionPack).unwrap();
        registry.install(&SafetyCollectionPack).unwrap();
        registry.install(&HumanMarkerCollectionPack).unwrap();
        let mut builder = ArtifactDbBuilder::new();
        registry
            .run_artifact_passes(artifact, &mut builder)
            .unwrap();
        let artifact = builder.finalize(registry.schemas()).unwrap();
        (registry, artifact)
    }

    fn marker_schema_ids() -> BTreeSet<SchemaId> {
        [
            MarkerOccurrenceEntity::ID,
            MarkerClaimEntity::ID,
            MarkerOccurrenceHasSourceAnchor::ID,
            MarkerOccurrenceHasClaim::ID,
            FunctionHasMarkerClaimCandidate::ID,
            CallOccurrenceHasMarkerClaimCandidate::ID,
            EffectSiteHasMarkerClaimCandidate::ID,
            UnsafeOperationHasMarkerClaimCandidate::ID,
        ]
        .into_iter()
        .map(|id| SchemaId::new(id).unwrap())
        .collect()
    }

    #[test]
    fn marker_collection_pack_registers_one_exact_producer_contract() {
        let mut registry = AnalysisRegistry::<CollectedArtifact>::new();
        registry.install(&CoreProgramCollectionPack).unwrap();
        registry.install(&SafetyCollectionPack).unwrap();
        registry.install(&HumanMarkerCollectionPack).unwrap();

        let producer = registry
            .artifact_passes()
            .descriptors()
            .find(|descriptor| descriptor.id.as_str() == "sniff-test.human.collect-markers")
            .expect("marker collection pass");
        assert_eq!(
            producer.writes.iter().cloned().collect::<BTreeSet<_>>(),
            marker_schema_ids()
        );
        assert_eq!(
            producer.reads.iter().cloned().collect::<BTreeSet<_>>(),
            [
                FunctionEntity::ID,
                CallOccurrenceEntity::ID,
                EffectSiteEntity::ID,
                UnsafeOperationEntity::ID,
                SourceAnchorEntity::ID,
            ]
            .into_iter()
            .map(|id| SchemaId::new(id).unwrap())
            .collect()
        );
    }

    #[test]
    fn empty_marker_collection_materializes_every_marker_table() {
        let (_, artifact) = collect(&empty_artifact());
        for schema in marker_schema_ids() {
            let table = artifact
                .tables
                .iter()
                .find(|table| table.schema == schema)
                .expect("declared empty marker table");
            assert!(table.rows.is_empty(), "{schema}");
        }
    }

    #[test]
    fn marker_collection_emits_complete_deterministic_typed_relations() {
        let (registry, forward) = collect(&artifact(false));
        let (_, reversed) = collect(&artifact(true));
        assert_eq!(forward, reversed);

        let view = ArtifactDbView::open(&forward, registry.schemas()).unwrap();
        assert_eq!(view.table::<MarkerOccurrenceEntity>().unwrap().len(), 2);
        assert_eq!(view.table::<MarkerClaimEntity>().unwrap().len(), 2);
        assert_eq!(
            view.relations::<MarkerOccurrenceHasSourceAnchor>()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            view.relations::<MarkerOccurrenceHasClaim>().unwrap().len(),
            2
        );
        assert_eq!(
            view.relations::<FunctionHasMarkerClaimCandidate>()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            view.relations::<CallOccurrenceHasMarkerClaimCandidate>()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            view.relations::<EffectSiteHasMarkerClaimCandidate>()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            view.relations::<UnsafeOperationHasMarkerClaimCandidate>()
                .unwrap()
                .len(),
            2
        );
    }
}
