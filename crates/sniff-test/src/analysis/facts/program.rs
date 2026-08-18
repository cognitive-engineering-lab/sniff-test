//! Core program entities and provenance relations shared by analysis packs.

use std::fmt::{self, Display, Formatter};

use reachability::MirBodyLocation;
use serde::{Deserialize, Serialize};

use super::pack::{AnalysisPack, AnalysisRegistry, PackRegistrationError};
use super::schema::{EntitySchema, RelationSchema, RowSchema};
use crate::namespace::{StableDefPathHash, StableExpansionHash, StableInstanceHash};

pub(crate) mod collector;

pub(crate) mod root_traversal;

pub(crate) mod topology;

pub(crate) mod workspace_index;

/// Stable identity of a generic definition or one exact rustc instance.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct FunctionKey {
    definition: StableDefPathHash,
    instance: Option<StableInstanceHash>,
}

impl FunctionKey {
    #[must_use]
    pub(crate) const fn new(
        definition: StableDefPathHash,
        instance: Option<StableInstanceHash>,
    ) -> Self {
        Self {
            definition,
            instance,
        }
    }

    #[must_use]
    pub(crate) const fn definition(self) -> StableDefPathHash {
        self.definition
    }

    #[must_use]
    pub(crate) const fn instance(self) -> Option<StableInstanceHash> {
        self.instance
    }
}

/// Why the current artifact owns one function body row.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub(crate) enum FunctionBodyProvenance {
    DefiningArtifact,
    ConsumerInstantiation { consumer_stable_crate_id: u64 },
}

/// One function body known to the artifact collector.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct FunctionEntity {
    key: FunctionKey,
    display_path: String,
    provenance: FunctionBodyProvenance,
}

impl RowSchema for FunctionEntity {
    const ID: &'static str = "sniff-test.core.function";
    const VERSION: u32 = 1;
}

impl EntitySchema for FunctionEntity {
    type Key = FunctionKey;

    fn key(&self) -> Self::Key {
        self.key
    }
}

impl FunctionEntity {
    #[must_use]
    pub(crate) fn new(
        key: FunctionKey,
        display_path: impl Into<String>,
        provenance: FunctionBodyProvenance,
    ) -> Self {
        Self {
            key,
            display_path: display_path.into(),
            provenance,
        }
    }

    #[must_use]
    pub(crate) const fn key(&self) -> &FunctionKey {
        &self.key
    }

    #[must_use]
    pub(crate) fn display_path(&self) -> &str {
        &self.display_path
    }

    #[must_use]
    pub(crate) const fn provenance(&self) -> FunctionBodyProvenance {
        self.provenance
    }
}

/// Persisted MIR coordinate does not fit the bounded artifact representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MirCoordinateError {
    coordinate: &'static str,
    value: usize,
}

impl Display for MirCoordinateError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "MIR {} coordinate {} exceeds the artifact limit",
            self.coordinate, self.value
        )
    }
}

impl std::error::Error for MirCoordinateError {}

/// Exact identity of one effect relative to its owning MIR body.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct EffectSiteKey {
    function: FunctionKey,
    basic_block: u32,
    statement_index: u32,
}

impl EffectSiteKey {
    pub(crate) fn from_mir(
        function: FunctionKey,
        location: MirBodyLocation,
    ) -> Result<Self, MirCoordinateError> {
        let basic_block = u32::try_from(location.basic_block).map_err(|_| MirCoordinateError {
            coordinate: "basic-block",
            value: location.basic_block,
        })?;
        let statement_index =
            u32::try_from(location.statement_index).map_err(|_| MirCoordinateError {
                coordinate: "statement-index",
                value: location.statement_index,
            })?;
        Ok(Self {
            function,
            basic_block,
            statement_index,
        })
    }

    #[must_use]
    pub(crate) const fn function(&self) -> &FunctionKey {
        &self.function
    }

    #[must_use]
    pub(crate) const fn basic_block(&self) -> u32 {
        self.basic_block
    }

    #[must_use]
    pub(crate) const fn statement_index(&self) -> u32 {
        self.statement_index
    }
}

/// Verified source file and integrity metadata from the legacy source layer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct SourceFileEntity {
    id: String,
    filename: String,
    content_hash: String,
    byte_len: u64,
}

impl RowSchema for SourceFileEntity {
    const ID: &'static str = "sniff-test.core.source-file";
    const VERSION: u32 = 1;
}

impl EntitySchema for SourceFileEntity {
    type Key = String;

    fn key(&self) -> Self::Key {
        self.id.clone()
    }
}

impl SourceFileEntity {
    #[must_use]
    pub(crate) fn new(
        id: impl Into<String>,
        filename: impl Into<String>,
        content_hash: impl Into<String>,
        byte_len: u64,
    ) -> Self {
        Self {
            id: id.into(),
            filename: filename.into(),
            content_hash: content_hash.into(),
            byte_len,
        }
    }

    #[must_use]
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub(crate) fn filename(&self) -> &str {
        &self.filename
    }

    #[must_use]
    pub(crate) fn content_hash(&self) -> &str {
        &self.content_hash
    }

    #[must_use]
    pub(crate) const fn byte_len(&self) -> u64 {
        self.byte_len
    }
}

/// Stable file-relative identity of one verified source range.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct SourceAnchorKey {
    file: String,
    byte_start: u64,
    byte_end: u64,
}

impl SourceAnchorKey {
    #[must_use]
    pub(crate) fn new(file: impl Into<String>, byte_start: u64, byte_end: u64) -> Self {
        Self {
            file: file.into(),
            byte_start,
            byte_end,
        }
    }

    #[must_use]
    pub(crate) fn file(&self) -> &str {
        &self.file
    }

    #[must_use]
    pub(crate) const fn byte_start(&self) -> u64 {
        self.byte_start
    }

    #[must_use]
    pub(crate) const fn byte_end(&self) -> u64 {
        self.byte_end
    }
}

/// One source range already checked against its source-file integrity row.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct SourceAnchorEntity {
    key: SourceAnchorKey,
}

impl RowSchema for SourceAnchorEntity {
    const ID: &'static str = "sniff-test.core.source-anchor";
    const VERSION: u32 = 1;
}

impl EntitySchema for SourceAnchorEntity {
    type Key = SourceAnchorKey;

    fn key(&self) -> Self::Key {
        self.key.clone()
    }
}

impl SourceAnchorEntity {
    #[must_use]
    pub(crate) const fn new(key: SourceAnchorKey) -> Self {
        Self { key }
    }

    #[must_use]
    pub(crate) const fn anchor(&self) -> &SourceAnchorKey {
        &self.key
    }
}

/// One assertion or other effect at an exact body-relative MIR coordinate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct EffectSiteEntity {
    key: EffectSiteKey,
}

impl RowSchema for EffectSiteEntity {
    const ID: &'static str = "sniff-test.core.effect-site";
    const VERSION: u32 = 1;
}

impl EntitySchema for EffectSiteEntity {
    type Key = EffectSiteKey;

    fn key(&self) -> Self::Key {
        self.key
    }
}

impl EffectSiteEntity {
    #[must_use]
    pub(crate) const fn new(key: EffectSiteKey) -> Self {
        Self { key }
    }

    #[must_use]
    pub(crate) const fn site(&self) -> &EffectSiteKey {
        &self.key
    }
}

/// Path-relative identity of one macro frame that produced an effect site.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct MacroExpansionKey {
    effect_site: EffectSiteKey,
    depth: u32,
}

impl MacroExpansionKey {
    #[must_use]
    pub(crate) const fn new(effect_site: EffectSiteKey, depth: u32) -> Self {
        Self { effect_site, depth }
    }

    #[must_use]
    pub(crate) const fn effect_site(&self) -> &EffectSiteKey {
        &self.effect_site
    }

    #[must_use]
    pub(crate) const fn depth(&self) -> u32 {
        self.depth
    }
}

/// One ordered macro-expansion frame on the provenance path to an effect.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct MacroExpansionEntity {
    key: MacroExpansionKey,
    expansion_hash: StableExpansionHash,
    macro_definition: StableDefPathHash,
    display_path: String,
}

impl RowSchema for MacroExpansionEntity {
    const ID: &'static str = "sniff-test.core.macro-expansion";
    const VERSION: u32 = 2;
}

impl EntitySchema for MacroExpansionEntity {
    type Key = MacroExpansionKey;

    fn key(&self) -> Self::Key {
        self.key.clone()
    }
}

impl MacroExpansionEntity {
    #[must_use]
    pub(crate) fn new(
        key: MacroExpansionKey,
        expansion_hash: StableExpansionHash,
        macro_definition: StableDefPathHash,
        display_path: impl Into<String>,
    ) -> Self {
        Self {
            key,
            expansion_hash,
            macro_definition,
            display_path: display_path.into(),
        }
    }

    #[must_use]
    pub(crate) const fn expansion(&self) -> &MacroExpansionKey {
        &self.key
    }

    #[must_use]
    pub(crate) const fn macro_definition(&self) -> StableDefPathHash {
        self.macro_definition
    }

    #[must_use]
    pub(crate) const fn expansion_hash(&self) -> StableExpansionHash {
        self.expansion_hash
    }

    #[must_use]
    pub(crate) fn display_path(&self) -> &str {
        &self.display_path
    }
}

macro_rules! empty_relation {
    ($name:ident, $id:literal, $from:ty, $to:ty) => {
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
    SourceAnchorInFile,
    "sniff-test.core.source-anchor-in-file",
    SourceAnchorEntity,
    SourceFileEntity
);
empty_relation!(
    FunctionOwnsEffectSite,
    "sniff-test.core.function-owns-effect-site",
    FunctionEntity,
    EffectSiteEntity
);
empty_relation!(
    FunctionHasSourceAnchor,
    "sniff-test.core.function-has-source-anchor",
    FunctionEntity,
    SourceAnchorEntity
);
empty_relation!(
    FunctionEntersMacroExpansion,
    "sniff-test.core.function-enters-macro-expansion",
    FunctionEntity,
    MacroExpansionEntity
);
empty_relation!(
    MacroExpansionEntersMacroExpansion,
    "sniff-test.core.macro-expansion-enters-macro-expansion",
    MacroExpansionEntity,
    MacroExpansionEntity
);
empty_relation!(
    MacroExpansionProducesEffectSite,
    "sniff-test.core.macro-expansion-produces-effect-site",
    MacroExpansionEntity,
    EffectSiteEntity
);
empty_relation!(
    MacroExpansionHasCallsite,
    "sniff-test.core.macro-expansion-has-callsite",
    MacroExpansionEntity,
    SourceAnchorEntity
);

/// Which source representation one anchor has for an effect site.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum EffectSourceAnchorRole {
    Presentation,
    Expanded,
}

/// Connects an effect site to a verified presentation or expanded anchor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct EffectSiteHasSourceAnchor {
    role: EffectSourceAnchorRole,
}

impl RowSchema for EffectSiteHasSourceAnchor {
    const ID: &'static str = "sniff-test.core.effect-site-has-source-anchor";
    const VERSION: u32 = 1;
}

impl RelationSchema for EffectSiteHasSourceAnchor {
    type From = EffectSiteEntity;
    type To = SourceAnchorEntity;
}

impl EffectSiteHasSourceAnchor {
    #[must_use]
    pub(crate) const fn new(role: EffectSourceAnchorRole) -> Self {
        Self { role }
    }

    #[must_use]
    pub(crate) const fn role(&self) -> EffectSourceAnchorRole {
        self.role
    }
}

/// Core schemas that give domain packs stable program and source endpoints.
pub(crate) struct CoreProgramPack;

impl<C: ?Sized> AnalysisPack<C> for CoreProgramPack {
    fn register(&self, registry: &mut AnalysisRegistry<C>) -> Result<(), PackRegistrationError> {
        registry.register_entity::<SourceFileEntity>()?;
        registry.register_entity::<SourceAnchorEntity>()?;
        registry.register_entity::<FunctionEntity>()?;
        registry.register_entity::<EffectSiteEntity>()?;
        registry.register_entity::<MacroExpansionEntity>()?;
        registry.register_relation::<SourceAnchorInFile>()?;
        registry.register_relation::<FunctionOwnsEffectSite>()?;
        registry.register_relation::<FunctionHasSourceAnchor>()?;
        registry.register_relation::<EffectSiteHasSourceAnchor>()?;
        registry.register_relation::<FunctionEntersMacroExpansion>()?;
        registry.register_relation::<MacroExpansionEntersMacroExpansion>()?;
        registry.register_relation::<MacroExpansionProducesEffectSite>()?;
        registry.register_relation::<MacroExpansionHasCallsite>()?;
        topology::register(registry)?;
        workspace_index::register_composition(registry)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use reachability::MirBodyLocation;

    use super::{
        CoreProgramPack, EffectSiteEntity, EffectSiteHasSourceAnchor, EffectSiteKey,
        EffectSourceAnchorRole, FunctionBodyProvenance, FunctionEntity, FunctionHasSourceAnchor,
        FunctionKey, FunctionOwnsEffectSite, MacroExpansionEntity, MacroExpansionHasCallsite,
        MacroExpansionKey, SourceAnchorEntity, SourceAnchorInFile, SourceAnchorKey,
        SourceFileEntity,
    };
    use crate::analysis::facts::pack::AnalysisRegistry;
    use crate::analysis::facts::schema::RowSchema;
    use crate::namespace::{StableDefPathHash, StableExpansionHash, StableInstanceHash};

    fn definition(value: &str) -> StableDefPathHash {
        serde_json::from_str(&format!("\"{value}\"")).expect("valid definition hash")
    }

    fn instance(value: &str) -> StableInstanceHash {
        serde_json::from_str(&format!("\"{value}\"")).expect("valid instance hash")
    }

    fn expansion(value: &str) -> StableExpansionHash {
        serde_json::from_str(&format!("\"{value}\"")).expect("valid expansion hash")
    }

    #[test]
    fn stable_program_keys_reject_unknown_fields() {
        assert!(
            serde_json::from_value::<FunctionKey>(serde_json::json!({
                "definition": "00000000000000010000000000000002",
                "instance": null,
                "unexpected": true,
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<SourceAnchorKey>(serde_json::json!({
                "file": "src/lib.rs",
                "byte-start": 0,
                "byte-end": 1,
                "unexpected": true,
            }))
            .is_err()
        );
    }

    #[test]
    fn effect_site_identity_retains_exact_instance_and_mir_coordinates() {
        let function = FunctionKey::new(
            definition("00000000000000010000000000000002"),
            Some(instance("00000000000000030000000000000004")),
        );
        let entity = FunctionEntity::new(
            function,
            "dependency::generic::<Local>",
            FunctionBodyProvenance::ConsumerInstantiation {
                consumer_stable_crate_id: 17,
            },
        );
        let site = EffectSiteKey::from_mir(
            *entity.key(),
            MirBodyLocation {
                basic_block: 6,
                statement_index: 9,
            },
        )
        .expect("MIR coordinates fit the persisted representation");

        assert_eq!(site.function(), entity.key());
        assert_eq!(site.basic_block(), 6);
        assert_eq!(site.statement_index(), 9);
        assert_eq!(
            entity.provenance(),
            FunctionBodyProvenance::ConsumerInstantiation {
                consumer_stable_crate_id: 17,
            }
        );
    }

    #[test]
    fn source_and_macro_entities_expose_verified_typed_provenance() {
        let source = SourceFileEntity::new("source-1", "src/lib.rs", "hash-1", 128);
        assert_eq!(source.id(), "source-1");
        assert_eq!(source.filename(), "src/lib.rs");
        assert_eq!(source.content_hash(), "hash-1");
        assert_eq!(source.byte_len(), 128);

        let anchor = SourceAnchorEntity::new(SourceAnchorKey::new("source-1", 7, 19));
        assert_eq!(anchor.anchor().file(), "source-1");
        assert_eq!(anchor.anchor().byte_start(), 7);
        assert_eq!(anchor.anchor().byte_end(), 19);

        let function = FunctionKey::new(
            definition("00000000000000010000000000000002"),
            Some(instance("00000000000000030000000000000004")),
        );
        let site = EffectSiteKey::from_mir(
            function,
            MirBodyLocation {
                basic_block: 2,
                statement_index: 5,
            },
        )
        .unwrap();
        let macro_expansion = MacroExpansionEntity::new(
            MacroExpansionKey::new(site, 1),
            expansion("00000000000000070000000000000008"),
            definition("00000000000000050000000000000006"),
            "dependency::checked",
        );
        assert_eq!(macro_expansion.expansion().effect_site(), &site);
        assert_eq!(macro_expansion.expansion().depth(), 1);
        assert_eq!(
            macro_expansion.macro_definition(),
            definition("00000000000000050000000000000006")
        );
        assert_eq!(
            macro_expansion.expansion_hash(),
            expansion("00000000000000070000000000000008")
        );
        assert_eq!(macro_expansion.display_path(), "dependency::checked");
        assert_eq!(MacroExpansionEntity::VERSION, 2);
        let mut missing_identity = serde_json::to_value(&macro_expansion).unwrap();
        missing_identity
            .as_object_mut()
            .unwrap()
            .remove("expansion-hash");
        assert!(serde_json::from_value::<MacroExpansionEntity>(missing_identity).is_err());

        assert_eq!(
            EffectSiteHasSourceAnchor::new(EffectSourceAnchorRole::Expanded).role(),
            EffectSourceAnchorRole::Expanded
        );
    }

    #[test]
    fn core_program_pack_registers_typed_program_provenance() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry
            .install(&CoreProgramPack)
            .expect("core program schemas register");

        for entity in [
            SourceFileEntity::ID,
            SourceAnchorEntity::ID,
            FunctionEntity::ID,
            EffectSiteEntity::ID,
            MacroExpansionEntity::ID,
        ] {
            assert!(
                registry
                    .schemas()
                    .descriptor(&entity.parse().unwrap())
                    .is_some()
            );
        }
        for relation in [
            SourceAnchorInFile::ID,
            FunctionHasSourceAnchor::ID,
            FunctionOwnsEffectSite::ID,
            MacroExpansionHasCallsite::ID,
        ] {
            assert!(
                registry
                    .schemas()
                    .descriptor(&relation.parse().unwrap())
                    .is_some()
            );
        }
    }
}
