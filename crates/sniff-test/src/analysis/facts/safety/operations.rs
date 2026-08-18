//! Typed unsafe-operation facts and provenance.

use serde::{Deserialize, Serialize};

use crate::namespace::{StableDefPathHash, StableExpansionHash};
pub(crate) use crate::safety::SafetyOpKind as SafetyOperationKind;

use super::super::pack::{AnalysisRegistry, PackRegistrationError};
use super::super::program::topology::SafetyEffectGroupEntity;
use super::super::program::{FunctionEntity, FunctionKey, SourceAnchorEntity};
use super::super::schema::{EntitySchema, RelationSchema, RowSchema};

/// Stable artifact identity of one operation discovered from a THIR body.
///
/// `local_id` is assigned from a deterministic sequence of operation
/// occurrences within the owning function identity. No MIR coordinate
/// participates in this identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct UnsafeOperationKey {
    owner: FunctionKey,
    local_id: u32,
}

impl UnsafeOperationKey {
    #[must_use]
    pub(crate) const fn new(owner: FunctionKey, local_id: u32) -> Self {
        Self { owner, local_id }
    }

    #[must_use]
    pub(crate) const fn owner(&self) -> &FunctionKey {
        &self.owner
    }

    #[must_use]
    pub(crate) const fn local_id(&self) -> u32 {
        self.local_id
    }
}

/// One policy-neutral operation that rustc requires to occur in an unsafe context.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct UnsafeOperationEntity {
    key: UnsafeOperationKey,
    kind: SafetyOperationKind,
}

impl RowSchema for UnsafeOperationEntity {
    const ID: &'static str = "sniff-test.safety.unsafe-operation";
    const VERSION: u32 = 1;
}

impl EntitySchema for UnsafeOperationEntity {
    type Key = UnsafeOperationKey;

    fn key(&self) -> Self::Key {
        self.key
    }
}

impl UnsafeOperationEntity {
    #[must_use]
    pub(crate) const fn new(key: UnsafeOperationKey, kind: SafetyOperationKind) -> Self {
        Self { key, kind }
    }

    #[must_use]
    pub(crate) const fn key(&self) -> &UnsafeOperationKey {
        &self.key
    }

    #[must_use]
    pub(crate) const fn kind(&self) -> SafetyOperationKind {
        self.kind
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
    /// Connects an owning function body to one THIR unsafe operation.
    FunctionOwnsUnsafeOperation,
    "sniff-test.safety.function-owns-unsafe-operation",
    FunctionEntity,
    UnsafeOperationEntity
);
empty_relation!(
    /// Places an unsafe operation in its source-level safety effect group.
    UnsafeOperationInSafetyEffectGroup,
    "sniff-test.safety.unsafe-operation-in-safety-effect-group",
    UnsafeOperationEntity,
    SafetyEffectGroupEntity
);

/// Which verified source representation an anchor has for an unsafe operation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum UnsafeOperationSourceAnchorRole {
    Presentation,
    Expanded,
}

/// Connects an unsafe operation to a verified presentation or expanded anchor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct UnsafeOperationHasSourceAnchor {
    role: UnsafeOperationSourceAnchorRole,
}

impl RowSchema for UnsafeOperationHasSourceAnchor {
    const ID: &'static str = "sniff-test.safety.unsafe-operation-has-source-anchor";
    const VERSION: u32 = 1;
}

impl RelationSchema for UnsafeOperationHasSourceAnchor {
    type From = UnsafeOperationEntity;
    type To = SourceAnchorEntity;
}

impl UnsafeOperationHasSourceAnchor {
    #[must_use]
    pub(crate) const fn new(role: UnsafeOperationSourceAnchorRole) -> Self {
        Self { role }
    }

    #[must_use]
    pub(crate) const fn role(&self) -> UnsafeOperationSourceAnchorRole {
        self.role
    }
}

/// Operation-relative identity of one ordered macro-expansion frame.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct UnsafeOperationMacroExpansionKey {
    operation: UnsafeOperationKey,
    depth: u32,
}

impl UnsafeOperationMacroExpansionKey {
    #[must_use]
    pub(crate) const fn new(operation: UnsafeOperationKey, depth: u32) -> Self {
        Self { operation, depth }
    }

    #[must_use]
    pub(crate) const fn operation(&self) -> &UnsafeOperationKey {
        &self.operation
    }

    #[must_use]
    pub(crate) const fn depth(&self) -> u32 {
        self.depth
    }
}

/// One ordered macro-expansion frame that produced an unsafe operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct UnsafeOperationMacroExpansionEntity {
    key: UnsafeOperationMacroExpansionKey,
    expansion_hash: StableExpansionHash,
    macro_definition: StableDefPathHash,
    display_path: String,
}

impl RowSchema for UnsafeOperationMacroExpansionEntity {
    const ID: &'static str = "sniff-test.safety.unsafe-operation-macro-expansion";
    const VERSION: u32 = 2;
}

impl EntitySchema for UnsafeOperationMacroExpansionEntity {
    type Key = UnsafeOperationMacroExpansionKey;

    fn key(&self) -> Self::Key {
        self.key
    }
}

impl UnsafeOperationMacroExpansionEntity {
    #[must_use]
    pub(crate) fn new(
        key: UnsafeOperationMacroExpansionKey,
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
    pub(crate) const fn key(&self) -> &UnsafeOperationMacroExpansionKey {
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

empty_relation!(
    /// Starts an operation-specific macro path at its owning function.
    FunctionEntersUnsafeOperationMacroExpansion,
    "sniff-test.safety.function-enters-unsafe-operation-macro-expansion",
    FunctionEntity,
    UnsafeOperationMacroExpansionEntity
);
empty_relation!(
    /// Connects adjacent outer-to-inner unsafe-operation macro frames.
    UnsafeOperationMacroExpansionEntersUnsafeOperationMacroExpansion,
    "sniff-test.safety.unsafe-operation-macro-expansion-enters-unsafe-operation-macro-expansion",
    UnsafeOperationMacroExpansionEntity,
    UnsafeOperationMacroExpansionEntity
);
empty_relation!(
    /// Terminates an ordered macro path at its unsafe-operation occurrence.
    UnsafeOperationMacroExpansionProducesUnsafeOperation,
    "sniff-test.safety.unsafe-operation-macro-expansion-produces-unsafe-operation",
    UnsafeOperationMacroExpansionEntity,
    UnsafeOperationEntity
);
empty_relation!(
    /// Connects an operation macro frame to its verified invocation anchor.
    UnsafeOperationMacroExpansionHasCallsite,
    "sniff-test.safety.unsafe-operation-macro-expansion-has-callsite",
    UnsafeOperationMacroExpansionEntity,
    SourceAnchorEntity
);

pub(super) fn register<C: ?Sized>(
    registry: &mut AnalysisRegistry<C>,
) -> Result<(), PackRegistrationError> {
    registry.register_entity::<UnsafeOperationEntity>()?;
    registry.register_entity::<UnsafeOperationMacroExpansionEntity>()?;
    registry.register_relation::<FunctionOwnsUnsafeOperation>()?;
    registry.register_relation::<UnsafeOperationInSafetyEffectGroup>()?;
    registry.register_relation::<UnsafeOperationHasSourceAnchor>()?;
    registry.register_relation::<FunctionEntersUnsafeOperationMacroExpansion>()?;
    registry
        .register_relation::<UnsafeOperationMacroExpansionEntersUnsafeOperationMacroExpansion>()?;
    registry.register_relation::<UnsafeOperationMacroExpansionProducesUnsafeOperation>()?;
    registry.register_relation::<UnsafeOperationMacroExpansionHasCallsite>()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        FunctionEntersUnsafeOperationMacroExpansion, FunctionOwnsUnsafeOperation,
        SafetyOperationKind, UnsafeOperationEntity, UnsafeOperationHasSourceAnchor,
        UnsafeOperationInSafetyEffectGroup, UnsafeOperationKey,
        UnsafeOperationMacroExpansionEntersUnsafeOperationMacroExpansion,
        UnsafeOperationMacroExpansionEntity, UnsafeOperationMacroExpansionHasCallsite,
        UnsafeOperationMacroExpansionKey, UnsafeOperationMacroExpansionProducesUnsafeOperation,
        UnsafeOperationSourceAnchorRole,
    };
    use crate::analysis::facts::builder::ArtifactDbBuilder;
    use crate::analysis::facts::encoded::{ArtifactFactIr, TableKind};
    use crate::analysis::facts::pack::AnalysisRegistry;
    use crate::analysis::facts::program::topology::{
        SafetyEffectGroupEntity, SafetyEffectGroupKey,
    };
    use crate::analysis::facts::program::{
        CoreProgramPack, FunctionBodyProvenance, FunctionEntity, FunctionKey, SourceAnchorEntity,
        SourceAnchorKey,
    };
    use crate::analysis::facts::safety::SafetyPack;
    use crate::analysis::facts::schema::{EntityHandle, EntitySchema, RelationSchema, RowSchema};
    use crate::analysis::facts::view::ArtifactDbView;
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

    fn exact_function() -> FunctionKey {
        FunctionKey::new(
            definition("00000000000000010000000000000002"),
            Some(instance("00000000000000030000000000000004")),
        )
    }

    fn assert_macro_expansion_entity_serde(operation: &UnsafeOperationEntity) {
        let frame = UnsafeOperationMacroExpansionEntity::new(
            UnsafeOperationMacroExpansionKey::new(*operation.key(), 2),
            expansion("00000000000000070000000000000008"),
            definition("00000000000000050000000000000006"),
            "dependency::unsafe_macro",
        );
        assert_eq!(frame.key().operation(), operation.key());
        assert_eq!(frame.key().depth(), 2);
        assert_eq!(
            frame.macro_definition(),
            definition("00000000000000050000000000000006")
        );
        assert_eq!(
            frame.expansion_hash(),
            expansion("00000000000000070000000000000008")
        );
        assert_eq!(frame.display_path(), "dependency::unsafe_macro");
        assert_eq!(UnsafeOperationMacroExpansionEntity::VERSION, 2);
        let frame_value = json!({
            "key": {
                "operation": {
                    "owner": {
                        "definition": "00000000000000010000000000000002",
                        "instance": "00000000000000030000000000000004"
                    },
                    "local-id": 9
                },
                "depth": 2
            },
            "expansion-hash": "00000000000000070000000000000008",
            "macro-definition": "00000000000000050000000000000006",
            "display-path": "dependency::unsafe_macro"
        });
        assert_eq!(serde_json::to_value(&frame).unwrap(), frame_value);
        assert_eq!(
            serde_json::from_value::<UnsafeOperationMacroExpansionEntity>(frame_value.clone())
                .unwrap(),
            frame
        );
        let mut missing_identity = frame_value.clone();
        missing_identity
            .as_object_mut()
            .unwrap()
            .remove("expansion-hash");
        assert!(
            serde_json::from_value::<UnsafeOperationMacroExpansionEntity>(missing_identity)
                .is_err()
        );
        let mut unknown_frame = frame_value;
        unknown_frame["unknown"] = json!(true);
        assert!(
            serde_json::from_value::<UnsafeOperationMacroExpansionEntity>(unknown_frame).is_err()
        );
    }

    fn serialized_kind(kind: SafetyOperationKind) -> &'static str {
        match kind {
            SafetyOperationKind::DerefRawPointer => "raw-pointer-dereference",
            SafetyOperationKind::UseOfMutableStatic => "mutable-static-access",
            SafetyOperationKind::UseOfExternStatic => "extern-static-access",
            SafetyOperationKind::AccessToUnionField => "union-field-access",
            SafetyOperationKind::UseOfUnsafeField => "unsafe-field-access",
            SafetyOperationKind::InitializingLayoutConstrainedType => {
                "layout-constrained-type-initialization"
            }
            SafetyOperationKind::InitializingTypeWithUnsafeField => "unsafe-field-initialization",
            SafetyOperationKind::MutationOfLayoutConstrainedField => {
                "layout-constrained-field-mutation"
            }
            SafetyOperationKind::BorrowOfLayoutConstrainedField => {
                "layout-constrained-field-borrow"
            }
            SafetyOperationKind::InlineAssembly => "inline-assembly",
            SafetyOperationKind::UnsafeBinderCast => "unsafe-binder-cast",
        }
    }

    #[test]
    fn operation_kind_exhaustively_matches_the_thir_taxonomy() {
        let kinds = [
            SafetyOperationKind::DerefRawPointer,
            SafetyOperationKind::UseOfMutableStatic,
            SafetyOperationKind::UseOfExternStatic,
            SafetyOperationKind::AccessToUnionField,
            SafetyOperationKind::UseOfUnsafeField,
            SafetyOperationKind::InitializingLayoutConstrainedType,
            SafetyOperationKind::InitializingTypeWithUnsafeField,
            SafetyOperationKind::MutationOfLayoutConstrainedField,
            SafetyOperationKind::BorrowOfLayoutConstrainedField,
            SafetyOperationKind::InlineAssembly,
            SafetyOperationKind::UnsafeBinderCast,
        ];

        assert_eq!(
            serde_json::to_value(kinds).unwrap(),
            json!([
                "raw-pointer-dereference",
                "mutable-static-access",
                "extern-static-access",
                "union-field-access",
                "unsafe-field-access",
                "layout-constrained-type-initialization",
                "unsafe-field-initialization",
                "layout-constrained-field-mutation",
                "layout-constrained-field-borrow",
                "inline-assembly",
                "unsafe-binder-cast"
            ])
        );
        for kind in kinds {
            let encoded = format!("\"{}\"", serialized_kind(kind));
            assert_eq!(serde_json::to_string(&kind).unwrap(), encoded);
            assert_eq!(
                serde_json::from_str::<SafetyOperationKind>(&encoded).unwrap(),
                kind
            );
        }
        assert!(serde_json::from_str::<SafetyOperationKind>("\"future-operation\"").is_err());
    }

    #[test]
    fn operation_identity_retains_exact_instance_and_thir_local_ordinal() {
        let definition = definition("00000000000000010000000000000002");
        let first_owner = FunctionKey::new(
            definition,
            Some(instance("00000000000000030000000000000004")),
        );
        let second_owner = FunctionKey::new(
            definition,
            Some(instance("00000000000000050000000000000006")),
        );
        let first = UnsafeOperationKey::new(first_owner, 7);

        assert_eq!(first.owner(), &first_owner);
        assert_eq!(first.local_id(), 7);
        assert_ne!(first, UnsafeOperationKey::new(first_owner, 8));
        assert_ne!(first, UnsafeOperationKey::new(second_owner, 7));
        assert_ne!(
            first,
            UnsafeOperationKey::new(FunctionKey::new(definition, None), 7)
        );

        let operation = UnsafeOperationEntity::new(
            first,
            SafetyOperationKind::MutationOfLayoutConstrainedField,
        );
        assert_eq!(operation.key(), &first);
        assert_eq!(
            operation.kind(),
            SafetyOperationKind::MutationOfLayoutConstrainedField
        );
        assert_eq!(EntitySchema::key(&operation), first);
    }

    #[test]
    fn operation_rows_have_deterministic_strict_serde() {
        let operation = UnsafeOperationEntity::new(
            UnsafeOperationKey::new(exact_function(), 9),
            SafetyOperationKind::DerefRawPointer,
        );
        let expected = json!({
            "key": {
                "owner": {
                    "definition": "00000000000000010000000000000002",
                    "instance": "00000000000000030000000000000004"
                },
                "local-id": 9
            },
            "kind": "raw-pointer-dereference"
        });
        assert_eq!(serde_json::to_value(&operation).unwrap(), expected);
        assert_eq!(
            serde_json::from_value::<UnsafeOperationEntity>(expected.clone()).unwrap(),
            operation
        );
        assert_eq!(
            serde_json::to_string(&operation).unwrap(),
            r#"{"key":{"owner":{"definition":"00000000000000010000000000000002","instance":"00000000000000030000000000000004"},"local-id":9},"kind":"raw-pointer-dereference"}"#
        );

        let mut unknown = expected;
        unknown["unknown"] = json!(true);
        assert!(serde_json::from_value::<UnsafeOperationEntity>(unknown).is_err());
        assert!(
            serde_json::from_value::<UnsafeOperationSourceAnchorRole>(json!("future-role"))
                .is_err()
        );

        assert_eq!(
            serde_json::to_value([
                UnsafeOperationSourceAnchorRole::Presentation,
                UnsafeOperationSourceAnchorRole::Expanded,
            ])
            .unwrap(),
            json!(["presentation", "expanded"])
        );

        assert_macro_expansion_entity_serde(&operation);

        assert_eq!(
            serde_json::to_value(FunctionOwnsUnsafeOperation::new()).unwrap(),
            json!({})
        );
        assert!(
            serde_json::from_value::<FunctionOwnsUnsafeOperation>(json!({ "unknown": true }))
                .is_err()
        );
        assert_eq!(
            serde_json::to_value(UnsafeOperationHasSourceAnchor::new(
                UnsafeOperationSourceAnchorRole::Presentation,
            ))
            .unwrap(),
            json!({ "role": "presentation" })
        );
        assert!(
            serde_json::from_value::<UnsafeOperationHasSourceAnchor>(json!({
                "role": "presentation",
                "unknown": true
            }))
            .is_err()
        );
    }

    #[test]
    fn safety_pack_registers_operation_group_source_and_macro_endpoints() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CoreProgramPack).unwrap();
        registry.install(&SafetyPack).unwrap();

        for (id, version) in [
            (UnsafeOperationEntity::ID, 1),
            (UnsafeOperationMacroExpansionEntity::ID, 2),
        ] {
            let descriptor = registry
                .schemas()
                .descriptor(&id.parse().unwrap())
                .unwrap_or_else(|| panic!("missing entity {id}"));
            assert_eq!(descriptor.kind(), TableKind::Entity);
            assert_eq!(descriptor.version(), version);
        }

        assert_endpoints::<FunctionOwnsUnsafeOperation>(
            &registry,
            FunctionEntity::ID,
            UnsafeOperationEntity::ID,
        );
        assert_endpoints::<UnsafeOperationInSafetyEffectGroup>(
            &registry,
            UnsafeOperationEntity::ID,
            SafetyEffectGroupEntity::ID,
        );
        assert_endpoints::<UnsafeOperationHasSourceAnchor>(
            &registry,
            UnsafeOperationEntity::ID,
            SourceAnchorEntity::ID,
        );
        assert_endpoints::<FunctionEntersUnsafeOperationMacroExpansion>(
            &registry,
            FunctionEntity::ID,
            UnsafeOperationMacroExpansionEntity::ID,
        );
        assert_endpoints::<UnsafeOperationMacroExpansionEntersUnsafeOperationMacroExpansion>(
            &registry,
            UnsafeOperationMacroExpansionEntity::ID,
            UnsafeOperationMacroExpansionEntity::ID,
        );
        assert_endpoints::<UnsafeOperationMacroExpansionProducesUnsafeOperation>(
            &registry,
            UnsafeOperationMacroExpansionEntity::ID,
            UnsafeOperationEntity::ID,
        );
        assert_endpoints::<UnsafeOperationMacroExpansionHasCallsite>(
            &registry,
            UnsafeOperationMacroExpansionEntity::ID,
            SourceAnchorEntity::ID,
        );
    }

    #[test]
    fn typed_view_opens_complete_operation_provenance() {
        let (registry, artifact, operation_key) = complete_operation_artifact();
        let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
        let (_, operation) = view
            .entity_by_key::<UnsafeOperationEntity>(&operation_key)
            .unwrap()
            .expect("typed unsafe operation");

        assert_eq!(operation.kind(), SafetyOperationKind::UseOfMutableStatic);
        assert_eq!(
            view.relations::<FunctionOwnsUnsafeOperation>()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            view.relations::<UnsafeOperationInSafetyEffectGroup>()
                .unwrap()
                .len(),
            1
        );
        let source_relations = view.relations::<UnsafeOperationHasSourceAnchor>().unwrap();
        assert_eq!(source_relations.len(), 2);
        assert!(source_relations.iter().any(|relation| {
            relation.data.role() == UnsafeOperationSourceAnchorRole::Presentation
        }));
        assert!(
            source_relations.iter().any(|relation| {
                relation.data.role() == UnsafeOperationSourceAnchorRole::Expanded
            })
        );
        assert_eq!(
            view.relations::<UnsafeOperationMacroExpansionEntersUnsafeOperationMacroExpansion>()
                .unwrap()
                .len(),
            1
        );
        let mut frame_depths = view
            .table::<UnsafeOperationMacroExpansionEntity>()
            .unwrap()
            .iter()
            .map(|frame| frame.key().depth())
            .collect::<Vec<_>>();
        frame_depths.sort_unstable();
        assert_eq!(frame_depths, [0, 1]);
        assert_eq!(
            view.relations::<FunctionEntersUnsafeOperationMacroExpansion>()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            view.relations::<UnsafeOperationMacroExpansionHasCallsite>()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            view.relations::<UnsafeOperationMacroExpansionProducesUnsafeOperation>()
                .unwrap()
                .len(),
            1
        );
    }

    fn complete_operation_artifact() -> (AnalysisRegistry<()>, ArtifactFactIr, UnsafeOperationKey) {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CoreProgramPack).unwrap();
        registry.install(&SafetyPack).unwrap();
        let mut builder = ArtifactDbBuilder::new();
        let owner = exact_function();
        let function = builder
            .insert_entity(&FunctionEntity::new(
                owner,
                "dependency::generic::<Local>",
                FunctionBodyProvenance::DefiningArtifact,
            ))
            .unwrap();
        let operation_key = UnsafeOperationKey::new(owner, 4);
        let operation = builder
            .insert_entity(&UnsafeOperationEntity::new(
                operation_key,
                SafetyOperationKind::UseOfMutableStatic,
            ))
            .unwrap();
        let group = builder
            .insert_entity(&SafetyEffectGroupEntity::new(SafetyEffectGroupKey::new(
                owner, 3,
            )))
            .unwrap();
        let [presentation, expanded, outer_callsite, inner_callsite] = [
            insert_anchor(&mut builder, "src/lib.rs", 10, 20),
            insert_anchor(&mut builder, "src/generated.rs", 30, 40),
            insert_anchor(&mut builder, "src/lib.rs", 8, 22),
            insert_anchor(&mut builder, "src/macros.rs", 50, 60),
        ];
        let outer = insert_macro_frame(
            &mut builder,
            operation_key,
            0,
            "0000000000000009000000000000000a",
            "00000000000000050000000000000006",
            "dependency::outer",
        );
        let inner = insert_macro_frame(
            &mut builder,
            operation_key,
            1,
            "000000000000000b000000000000000c",
            "00000000000000070000000000000008",
            "dependency::inner",
        );

        relate(
            &mut builder,
            &function,
            &operation,
            &FunctionOwnsUnsafeOperation::new(),
        );
        relate(
            &mut builder,
            &operation,
            &group,
            &UnsafeOperationInSafetyEffectGroup::new(),
        );
        for (anchor, role) in [
            (&presentation, UnsafeOperationSourceAnchorRole::Presentation),
            (&expanded, UnsafeOperationSourceAnchorRole::Expanded),
        ] {
            relate(
                &mut builder,
                &operation,
                anchor,
                &UnsafeOperationHasSourceAnchor::new(role),
            );
        }
        relate(
            &mut builder,
            &function,
            &outer,
            &FunctionEntersUnsafeOperationMacroExpansion::new(),
        );
        relate(
            &mut builder,
            &outer,
            &inner,
            &UnsafeOperationMacroExpansionEntersUnsafeOperationMacroExpansion::new(),
        );
        relate(
            &mut builder,
            &inner,
            &operation,
            &UnsafeOperationMacroExpansionProducesUnsafeOperation::new(),
        );
        for (frame, callsite) in [(&outer, &outer_callsite), (&inner, &inner_callsite)] {
            relate(
                &mut builder,
                frame,
                callsite,
                &UnsafeOperationMacroExpansionHasCallsite::new(),
            );
        }

        let artifact = builder.finalize(registry.schemas()).unwrap();
        (registry, artifact, operation_key)
    }

    fn insert_anchor(
        builder: &mut ArtifactDbBuilder,
        file: &str,
        byte_start: u64,
        byte_end: u64,
    ) -> EntityHandle<SourceAnchorEntity> {
        builder
            .insert_entity(&SourceAnchorEntity::new(SourceAnchorKey::new(
                file, byte_start, byte_end,
            )))
            .unwrap()
    }

    fn insert_macro_frame(
        builder: &mut ArtifactDbBuilder,
        operation: UnsafeOperationKey,
        depth: u32,
        expansion_hash: &str,
        macro_definition: &str,
        display_path: &str,
    ) -> EntityHandle<UnsafeOperationMacroExpansionEntity> {
        builder
            .insert_entity(&UnsafeOperationMacroExpansionEntity::new(
                UnsafeOperationMacroExpansionKey::new(operation, depth),
                expansion(expansion_hash),
                definition(macro_definition),
                display_path,
            ))
            .unwrap()
    }

    fn relate<R: RelationSchema>(
        builder: &mut ArtifactDbBuilder,
        from: &EntityHandle<R::From>,
        to: &EntityHandle<R::To>,
        relation: &R,
    ) {
        builder.relate(from, to, relation).unwrap();
    }

    fn assert_endpoints<R: RelationSchema>(registry: &AnalysisRegistry<()>, from: &str, to: &str) {
        let descriptor = registry
            .schemas()
            .descriptor(&R::ID.parse().unwrap())
            .expect("relation is registered");
        let endpoints = descriptor.relation_endpoints().expect("typed endpoints");
        assert_eq!(descriptor.kind(), TableKind::Relation);
        assert_eq!(descriptor.version(), 1);
        assert_eq!(endpoints.from.as_str(), from);
        assert_eq!(endpoints.to.as_str(), to);
    }
}
