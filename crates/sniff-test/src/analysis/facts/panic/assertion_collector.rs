//! Legacy-free collection of compiler assertions from validated core topology.

use std::collections::BTreeMap;

use super::model::{
    AlignedPointerRequirement, CompilerAssertRequirement, CoroutineStateRequirement,
    InBoundsRequirement, MirAssertFact, NoOverflowRequirement, NonNullPointerRequirement,
    NonZeroRequirement, OpaqueCompilerRequirement, ValidEnumRequirement,
};
use crate::analysis::collected::{CollectedArtifact, CollectedMirAssert};
use crate::analysis::facts::builder::FactMeta;
use crate::analysis::facts::pack::{AnalysisPack, AnalysisRegistry, PackRegistrationError};
use crate::analysis::facts::pass::{
    ArtifactPass, PassDescriptor, PassError, PassInput, PassOutput,
};
use crate::analysis::facts::program::{
    EffectSiteEntity, EffectSiteHasSourceAnchor, EffectSiteKey, EffectSourceAnchorRole,
    FunctionEntity, FunctionKey, FunctionOwnsEffectSite, SourceAnchorEntity,
};
use crate::analysis::facts::schema::{
    EntityHandle, PassId, RequirementSchema, RowSchema, SchemaId,
};

pub(crate) const COLLECT_MIR_ASSERTS_PASS: &str = "sniff-test.panic.collect-mir-asserts";

/// Composition pack for precise compiler assertions over committed core rows.
pub(crate) struct PanicAssertionCollectionPack;

impl AnalysisPack<CollectedArtifact> for PanicAssertionCollectionPack {
    fn register(
        &self,
        registry: &mut AnalysisRegistry<CollectedArtifact>,
    ) -> Result<(), PackRegistrationError> {
        register_artifact_schemas(registry)?;
        registry.register_artifact_pass(CollectMirAsserts)
    }
}

/// Registers the permanent compiler-assert artifact schemas without a pass.
pub(crate) fn register_artifact_schemas<C: ?Sized>(
    registry: &mut AnalysisRegistry<C>,
) -> Result<(), PackRegistrationError> {
    registry.register_fact::<MirAssertFact>()?;
    registry.register_requirement::<NonZeroRequirement>()?;
    registry.register_requirement::<InBoundsRequirement>()?;
    registry.register_requirement::<NoOverflowRequirement>()?;
    registry.register_requirement::<CoroutineStateRequirement>()?;
    registry.register_requirement::<AlignedPointerRequirement>()?;
    registry.register_requirement::<NonNullPointerRequirement>()?;
    registry.register_requirement::<ValidEnumRequirement>()?;
    registry.register_requirement::<OpaqueCompilerRequirement>()?;
    Ok(())
}

struct CollectMirAsserts;

impl ArtifactPass<CollectedArtifact> for CollectMirAsserts {
    fn descriptor(&self) -> PassDescriptor {
        PassDescriptor::new(PassId::new(COLLECT_MIR_ASSERTS_PASS).unwrap())
            .with_reads(core_read_schema_ids())
            .with_writes(assertion_schema_ids())
    }

    fn run(
        &mut self,
        cx: &CollectedArtifact,
        input: PassInput<'_>,
        output: &mut PassOutput<'_>,
    ) -> Result<(), PassError> {
        let core = CoreAssertionIndex::read(input)?;
        for assertion in cx.mir_asserts() {
            core.emit(assertion, output)?;
        }
        Ok(())
    }
}

fn schema<S: RowSchema>() -> SchemaId {
    SchemaId::new(S::ID).expect("built-in panic-assertion schema IDs are valid")
}

fn core_read_schema_ids() -> Vec<SchemaId> {
    vec![
        schema::<FunctionEntity>(),
        schema::<EffectSiteEntity>(),
        schema::<SourceAnchorEntity>(),
        schema::<FunctionOwnsEffectSite>(),
        schema::<EffectSiteHasSourceAnchor>(),
    ]
}

fn assertion_schema_ids() -> Vec<SchemaId> {
    vec![
        schema::<MirAssertFact>(),
        schema::<NonZeroRequirement>(),
        schema::<InBoundsRequirement>(),
        schema::<NoOverflowRequirement>(),
        schema::<CoroutineStateRequirement>(),
        schema::<AlignedPointerRequirement>(),
        schema::<NonNullPointerRequirement>(),
        schema::<ValidEnumRequirement>(),
        schema::<OpaqueCompilerRequirement>(),
    ]
}

#[derive(Default)]
struct SourceAnchors {
    presentation: Option<EntityHandle<SourceAnchorEntity>>,
    expanded: Option<EntityHandle<SourceAnchorEntity>>,
}

impl SourceAnchors {
    fn insert(
        &mut self,
        site: EffectSiteKey,
        role: EffectSourceAnchorRole,
        anchor: EntityHandle<SourceAnchorEntity>,
    ) -> Result<(), PassError> {
        let slot = match role {
            EffectSourceAnchorRole::Presentation => &mut self.presentation,
            EffectSourceAnchorRole::Expanded => &mut self.expanded,
        };
        if slot.replace(anchor).is_some() {
            return Err(PassError::failed(format!(
                "committed core topology has duplicate {role:?} source anchors for effect site {site:?}"
            )));
        }
        Ok(())
    }

    fn preferred(&self) -> Option<&EntityHandle<SourceAnchorEntity>> {
        self.presentation.as_ref().or(self.expanded.as_ref())
    }
}

struct CoreAssertionIndex {
    functions: BTreeMap<FunctionKey, EntityHandle<FunctionEntity>>,
    effects: BTreeMap<EffectSiteKey, EntityHandle<EffectSiteEntity>>,
    owners: BTreeMap<EffectSiteKey, EntityHandle<FunctionEntity>>,
    anchors: BTreeMap<EffectSiteKey, SourceAnchors>,
}

impl CoreAssertionIndex {
    fn read(input: PassInput<'_>) -> Result<Self, PassError> {
        let mut functions = BTreeMap::new();
        for entity in input.table::<FunctionEntity>()? {
            let key = *entity.key();
            if functions
                .insert(key, EntityHandle::from_entity(&entity))
                .is_some()
            {
                return Err(PassError::failed(format!(
                    "committed core topology has duplicate function entity {key:?}"
                )));
            }
        }

        let mut effects = BTreeMap::new();
        for entity in input.table::<EffectSiteEntity>()? {
            let site = *entity.site();
            if effects
                .insert(site, EntityHandle::from_entity(&entity))
                .is_some()
            {
                return Err(PassError::failed(format!(
                    "committed core topology has duplicate effect-site entity {site:?}"
                )));
            }
        }

        let mut source_anchors = BTreeMap::new();
        for entity in input.table::<SourceAnchorEntity>()? {
            let key = entity.anchor().clone();
            if source_anchors
                .insert(key.clone(), EntityHandle::from_entity(&entity))
                .is_some()
            {
                return Err(PassError::failed(format!(
                    "committed core topology has duplicate source-anchor entity {key:?}"
                )));
            }
        }

        let mut owners = BTreeMap::new();
        for relation in input.relations::<FunctionOwnsEffectSite>()? {
            let function = *relation.from.key();
            let site = *relation.to.key();
            if !functions.contains_key(&function) {
                return Err(PassError::failed(format!(
                    "committed core ownership references missing function {function:?}"
                )));
            }
            if !effects.contains_key(&site) {
                return Err(PassError::failed(format!(
                    "committed core ownership references missing effect site {site:?}"
                )));
            }
            if site.function() != &function {
                return Err(PassError::failed(format!(
                    "committed core ownership for effect site {site:?} uses the wrong function {function:?}"
                )));
            }
            if owners.insert(site, relation.from).is_some() {
                return Err(PassError::failed(format!(
                    "committed core topology has duplicate owners for effect site {site:?}"
                )));
            }
        }

        let mut anchors = BTreeMap::<EffectSiteKey, SourceAnchors>::new();
        for relation in input.relations::<EffectSiteHasSourceAnchor>()? {
            let site = *relation.from.key();
            let anchor = relation.to.key().clone();
            if !effects.contains_key(&site) {
                return Err(PassError::failed(format!(
                    "committed core source provenance references missing effect site {site:?}"
                )));
            }
            if !source_anchors.contains_key(&anchor) {
                return Err(PassError::failed(format!(
                    "committed core source provenance references missing anchor {anchor:?}"
                )));
            }
            anchors
                .entry(site)
                .or_default()
                .insert(site, relation.data.role(), relation.to)?;
        }

        Ok(Self {
            functions,
            effects,
            owners,
            anchors,
        })
    }

    fn emit(
        &self,
        assertion: &CollectedMirAssert,
        output: &mut PassOutput<'_>,
    ) -> Result<(), PassError> {
        let site_key = *assertion.site();
        let effect = self.effects.get(&site_key).ok_or_else(|| {
            PassError::failed(format!(
                "validated MIR assertion references missing committed effect site {site_key:?}"
            ))
        })?;
        let owner = self.owners.get(&site_key).ok_or_else(|| {
            PassError::failed(format!(
                "validated MIR assertion effect site {site_key:?} has no committed owner"
            ))
        })?;
        let function = self.functions.get(site_key.function()).ok_or_else(|| {
            PassError::failed(format!(
                "validated MIR assertion references missing committed function {:?}",
                site_key.function()
            ))
        })?;
        if owner != function {
            return Err(PassError::failed(format!(
                "validated MIR assertion effect site {site_key:?} has inconsistent committed ownership"
            )));
        }

        let mut metadata = output.fact_meta();
        metadata = output.with_fact_owner(metadata, effect)?;
        metadata = output.with_fact_provenance_root(metadata, function)?;
        if let Some(anchor) = self
            .anchors
            .get(&site_key)
            .and_then(SourceAnchors::preferred)
        {
            metadata = output.with_fact_anchor(metadata, anchor)?;
        }
        metadata =
            attach_compiler_requirement(output, metadata, assertion.kind().implicit_requirement())?;
        output.insert_fact(&MirAssertFact::new(assertion.kind()), metadata)
    }
}

fn attach_requirement<R: RequirementSchema>(
    output: &mut PassOutput<'_>,
    metadata: FactMeta,
    requirement: &R,
) -> Result<FactMeta, PassError> {
    let requirement = output.insert_requirement(requirement)?;
    output.with_fact_requirement(metadata, &requirement)
}

fn attach_compiler_requirement(
    output: &mut PassOutput<'_>,
    metadata: FactMeta,
    requirement: CompilerAssertRequirement,
) -> Result<FactMeta, PassError> {
    match requirement {
        CompilerAssertRequirement::NonZero(requirement) => {
            attach_requirement(output, metadata, &requirement)
        }
        CompilerAssertRequirement::InBounds(requirement) => {
            attach_requirement(output, metadata, &requirement)
        }
        CompilerAssertRequirement::NoOverflow(requirement) => {
            attach_requirement(output, metadata, &requirement)
        }
        CompilerAssertRequirement::CoroutineState(requirement) => {
            attach_requirement(output, metadata, &requirement)
        }
        CompilerAssertRequirement::AlignedPointer(requirement) => {
            attach_requirement(output, metadata, &requirement)
        }
        CompilerAssertRequirement::NonNullPointer(requirement) => {
            attach_requirement(output, metadata, &requirement)
        }
        CompilerAssertRequirement::ValidEnum(requirement) => {
            attach_requirement(output, metadata, &requirement)
        }
        CompilerAssertRequirement::Opaque(requirement) => {
            attach_requirement(output, metadata, &requirement)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use reachability::MirBodyLocation;

    use super::{COLLECT_MIR_ASSERTS_PASS, PanicAssertionCollectionPack};
    use crate::analysis::collected::{
        CollectedArtifact, CollectedArtifactInput, CollectedEffectSite,
        CollectedEffectSourceAnchor, CollectedFunctionBody, CollectedMirAssert, CollectedProgram,
    };
    use crate::analysis::facts::builder::ArtifactDbBuilder;
    use crate::analysis::facts::pack::AnalysisRegistry;
    use crate::analysis::facts::panic::model::{
        AlignedPointerRequirement, BinaryOverflowOperation, CoroutineStateRequirement,
        InBoundsRequirement, MirAssertFact, MirAssertKind, NoOverflowRequirement,
        NonNullPointerRequirement, NonZeroRequirement, OpaqueCompilerRequirement,
        ValidEnumRequirement,
    };
    use crate::analysis::facts::program::collector::CoreProgramCollectionPack;
    use crate::analysis::facts::program::topology::CallableEntity;
    use crate::analysis::facts::program::{
        EffectSiteEntity, EffectSiteHasSourceAnchor, EffectSiteKey, EffectSourceAnchorRole,
        FunctionBodyProvenance, FunctionEntity, FunctionKey, FunctionOwnsEffectSite,
        SourceAnchorEntity, SourceAnchorKey, SourceFileEntity,
    };
    use crate::analysis::facts::schema::{RowSchema, SchemaId};
    use crate::analysis::facts::view::ArtifactDbView;
    use crate::namespace::{StableDefPathHash, StableInstanceHash};

    fn definition(value: u128) -> StableDefPathHash {
        serde_json::from_str(&format!("\"{value:032x}\"")).expect("valid definition hash")
    }

    fn instance(value: u128) -> StableInstanceHash {
        serde_json::from_str(&format!("\"{value:032x}\"")).expect("valid instance hash")
    }

    fn owner() -> FunctionKey {
        FunctionKey::new(definition(1), Some(instance(101)))
    }

    fn site(basic_block: usize, statement_index: usize) -> EffectSiteKey {
        EffectSiteKey::from_mir(
            owner(),
            MirBodyLocation {
                basic_block,
                statement_index,
            },
        )
        .unwrap()
    }

    fn anchor(start: u64, end: u64) -> SourceAnchorKey {
        SourceAnchorKey::new("src/lib.rs", start, end)
    }

    fn artifact(reverse: bool, same_kind: bool) -> CollectedArtifact {
        let first_site = site(1, 2);
        let second_site = site(3, 4);
        let mut anchors = [anchor(0, 5), anchor(10, 15), anchor(20, 25), anchor(30, 35)]
            .into_iter()
            .map(SourceAnchorEntity::new)
            .collect::<Vec<_>>();
        let mut effects = vec![
            CollectedEffectSite::new(
                EffectSiteEntity::new(first_site),
                vec![
                    CollectedEffectSourceAnchor::new(
                        EffectSourceAnchorRole::Expanded,
                        anchor(20, 25),
                    ),
                    CollectedEffectSourceAnchor::new(
                        EffectSourceAnchorRole::Presentation,
                        anchor(10, 15),
                    ),
                ],
                Vec::new(),
            ),
            CollectedEffectSite::new(
                EffectSiteEntity::new(second_site),
                vec![CollectedEffectSourceAnchor::new(
                    EffectSourceAnchorRole::Expanded,
                    anchor(30, 35),
                )],
                Vec::new(),
            ),
        ];
        let mut assertions = vec![
            CollectedMirAssert::new(first_site, MirAssertKind::BoundsCheck),
            CollectedMirAssert::new(
                second_site,
                if same_kind {
                    MirAssertKind::BoundsCheck
                } else {
                    MirAssertKind::Overflow(BinaryOverflowOperation::Addition)
                },
            ),
        ];
        if reverse {
            anchors.reverse();
            effects.reverse();
            assertions.reverse();
        }
        let body = CollectedFunctionBody::new(
            FunctionEntity::new(
                owner(),
                "crate::body",
                FunctionBodyProvenance::DefiningArtifact,
            ),
            Some(anchor(0, 5)),
            Vec::new(),
            Vec::new(),
            effects,
        );
        let program = CollectedProgram::try_new(
            vec![SourceFileEntity::new(
                "src/lib.rs",
                "src/lib.rs",
                "verified-hash",
                100,
            )],
            anchors,
            vec![CallableEntity::new(
                owner(),
                "crate::body",
                false,
                false,
                true,
                false,
                vec![String::from("crate::body")],
            )],
            vec![body],
        )
        .unwrap();
        CollectedArtifact::try_new(CollectedArtifactInput {
            program,
            unsafe_operations: Vec::new(),
            panic_contracts: Vec::new(),
            safety_contracts: Vec::new(),
            mir_asserts: assertions,
            marker_occurrences: Vec::new(),
        })
        .unwrap()
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
        registry.install(&PanicAssertionCollectionPack).unwrap();
        let mut builder = ArtifactDbBuilder::new();
        registry
            .run_artifact_passes(artifact, &mut builder)
            .unwrap();
        let ir = builder.finalize(registry.schemas()).unwrap();
        (registry, ir)
    }

    fn assertion_schema_ids() -> BTreeSet<SchemaId> {
        [
            MirAssertFact::ID,
            NonZeroRequirement::ID,
            InBoundsRequirement::ID,
            NoOverflowRequirement::ID,
            CoroutineStateRequirement::ID,
            AlignedPointerRequirement::ID,
            NonNullPointerRequirement::ID,
            ValidEnumRequirement::ID,
            OpaqueCompilerRequirement::ID,
        ]
        .into_iter()
        .map(|id| SchemaId::new(id).unwrap())
        .collect()
    }

    fn core_read_schema_ids() -> BTreeSet<SchemaId> {
        [
            FunctionEntity::ID,
            EffectSiteEntity::ID,
            SourceAnchorEntity::ID,
            FunctionOwnsEffectSite::ID,
            EffectSiteHasSourceAnchor::ID,
        ]
        .into_iter()
        .map(|id| SchemaId::new(id).unwrap())
        .collect()
    }

    #[test]
    fn pack_reads_core_and_owns_only_assertion_schemas() {
        let mut registry = AnalysisRegistry::<CollectedArtifact>::new();
        registry.install(&CoreProgramCollectionPack).unwrap();
        registry.install(&PanicAssertionCollectionPack).unwrap();

        let descriptor = registry
            .artifact_passes()
            .descriptors()
            .find(|descriptor| descriptor.id.as_str() == COLLECT_MIR_ASSERTS_PASS)
            .unwrap();
        assert_eq!(
            descriptor.reads.iter().cloned().collect::<BTreeSet<_>>(),
            core_read_schema_ids()
        );
        assert_eq!(
            descriptor.writes.iter().cloned().collect::<BTreeSet<_>>(),
            assertion_schema_ids()
        );
        assert!(
            descriptor
                .writes
                .iter()
                .all(|schema| !core_read_schema_ids().contains(schema))
        );
    }

    #[test]
    fn empty_collection_materializes_every_assertion_table() {
        let (_, ir) = collect(&empty_artifact());
        for schema in assertion_schema_ids() {
            let table = ir
                .tables
                .iter()
                .find(|table| table.schema == schema)
                .unwrap();
            assert!(table.rows.is_empty());
        }
    }

    #[test]
    fn assertions_are_deterministic_and_use_exact_core_provenance() {
        let (registry, forward) = collect(&artifact(false, false));
        let (_, reversed) = collect(&artifact(true, false));
        assert_eq!(forward, reversed);

        let view = ArtifactDbView::open(&forward, registry.schemas()).unwrap();
        let root = view
            .entity_by_key::<FunctionEntity>(&owner())
            .unwrap()
            .unwrap()
            .0
            .erase();
        let facts = view.facts::<MirAssertFact>().unwrap();
        assert_eq!(facts.len(), 2);

        for (kind, effect_site, expected_anchor, expected_requirement) in [
            (
                MirAssertKind::BoundsCheck,
                site(1, 2),
                anchor(10, 15),
                InBoundsRequirement::ID,
            ),
            (
                MirAssertKind::Overflow(BinaryOverflowOperation::Addition),
                site(3, 4),
                anchor(30, 35),
                NoOverflowRequirement::ID,
            ),
        ] {
            let fact = facts
                .iter()
                .find(|fact| fact.fact.data.kind() == kind)
                .unwrap();
            let owner = view
                .entity_by_key::<EffectSiteEntity>(&effect_site)
                .unwrap()
                .unwrap()
                .0
                .erase();
            let anchor = view
                .entity_by_key::<SourceAnchorEntity>(&expected_anchor)
                .unwrap()
                .unwrap()
                .0
                .erase();
            assert_eq!(fact.metadata.producer.as_str(), COLLECT_MIR_ASSERTS_PASS);
            assert_eq!(fact.metadata.owner.as_ref(), Some(&owner));
            assert_eq!(fact.metadata.provenance_root.as_ref(), Some(&root));
            assert_eq!(fact.metadata.anchor.as_ref(), Some(&anchor));
            assert_eq!(fact.metadata.requirements.len(), 1);
            assert_eq!(
                fact.metadata.requirements[0].schema.as_str(),
                expected_requirement
            );
        }

        assert_eq!(view.table::<InBoundsRequirement>().unwrap().len(), 1);
        assert_eq!(view.table::<NoOverflowRequirement>().unwrap().len(), 1);
    }

    #[test]
    fn same_kind_at_distinct_sites_preserves_both_fact_occurrences() {
        let (registry, ir) = collect(&artifact(false, true));
        let view = ArtifactDbView::open(&ir, registry.schemas()).unwrap();
        let facts = view.facts::<MirAssertFact>().unwrap();
        assert_eq!(facts.len(), 2);
        assert!(
            facts
                .iter()
                .all(|fact| fact.fact.data.kind() == MirAssertKind::BoundsCheck)
        );
        assert_eq!(view.table::<InBoundsRequirement>().unwrap().len(), 1);
        assert_ne!(facts[0].metadata.owner, facts[1].metadata.owner);
    }
}
