//! Typed program-call topology shared by domain analysis packs.

use serde::{Deserialize, Deserializer, Serialize};

use super::super::schema::{EntitySchema, RelationSchema, RowSchema};
use super::{FunctionEntity, FunctionKey, SourceAnchorEntity};
use crate::namespace::{StableDefPathHash, StableExpansionHash, StableTypeHash};

/// Policy-relevant metadata for any callable referenced by program topology.
///
/// A callable is intentionally separate from `FunctionEntity`: the latter
/// proves that this artifact owns body facts, while this row can also describe
/// a declaration or boundary for which no Rust body exists.
#[allow(
    clippy::struct_excessive_bools,
    reason = "these independent compiler facts are not mutually exclusive state"
)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct CallableEntity {
    key: FunctionKey,
    display_path: String,
    is_unsafe: bool,
    is_exported: bool,
    has_rust_body: bool,
    is_foreign: bool,
    #[serde(deserialize_with = "deserialize_namespace_candidates")]
    namespace_candidates: Vec<String>,
}

impl RowSchema for CallableEntity {
    const ID: &'static str = "sniff-test.core.callable";
    const VERSION: u32 = 1;
}

impl EntitySchema for CallableEntity {
    type Key = FunctionKey;

    fn key(&self) -> Self::Key {
        self.key
    }
}

impl CallableEntity {
    #[must_use]
    #[allow(
        clippy::fn_params_excessive_bools,
        reason = "these named compiler flags are copied together and remain independently meaningful"
    )]
    pub(crate) fn new(
        key: FunctionKey,
        display_path: impl Into<String>,
        is_unsafe: bool,
        is_exported: bool,
        has_rust_body: bool,
        is_foreign: bool,
        mut namespace_candidates: Vec<String>,
    ) -> Self {
        canonicalize_namespace_candidates(&mut namespace_candidates);
        Self {
            key,
            display_path: display_path.into(),
            is_unsafe,
            is_exported,
            has_rust_body,
            is_foreign,
            namespace_candidates,
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
    pub(crate) const fn is_unsafe(&self) -> bool {
        self.is_unsafe
    }

    #[must_use]
    pub(crate) const fn is_exported(&self) -> bool {
        self.is_exported
    }

    #[must_use]
    pub(crate) const fn has_rust_body(&self) -> bool {
        self.has_rust_body
    }

    #[must_use]
    pub(crate) const fn is_foreign(&self) -> bool {
        self.is_foreign
    }

    #[must_use]
    pub(crate) fn namespace_candidates(&self) -> &[String] {
        &self.namespace_candidates
    }
}

fn canonicalize_namespace_candidates(candidates: &mut Vec<String>) {
    candidates.sort_unstable();
    candidates.dedup();
}

fn deserialize_namespace_candidates<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let mut candidates = Vec::<String>::deserialize(deserializer)?;
    canonicalize_namespace_candidates(&mut candidates);
    Ok(candidates)
}

macro_rules! owner_local_key {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
        #[serde(rename_all = "kebab-case", deny_unknown_fields)]
        pub(crate) struct $name {
            owner: FunctionKey,
            local_id: u32,
        }

        impl $name {
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
    };
}

owner_local_key!(
    /// Stable artifact-local identity of one source call site.
    CallSiteKey
);
owner_local_key!(
    /// Stable artifact-local identity of one resolved or structural call edge.
    CallOccurrenceKey
);
owner_local_key!(
    /// Stable artifact-local identity of one source-level safety effect group.
    SafetyEffectGroupKey
);

/// One source call site, shared by every callable endpoint derived from it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct CallSiteEntity {
    key: CallSiteKey,
}

impl RowSchema for CallSiteEntity {
    const ID: &'static str = "sniff-test.core.call-site";
    const VERSION: u32 = 1;
}

impl EntitySchema for CallSiteEntity {
    type Key = CallSiteKey;

    fn key(&self) -> Self::Key {
        self.key
    }
}

impl CallSiteEntity {
    #[must_use]
    pub(crate) const fn new(key: CallSiteKey) -> Self {
        Self { key }
    }

    #[must_use]
    pub(crate) const fn key(&self) -> &CallSiteKey {
        &self.key
    }
}

/// Complete mirror of the reachability edge variants stored as calls.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CallKind {
    DirectCall,
    TailCall,
    FnPointerReify,
    ClosureFnPointerReify,
    FnPointerCallTarget,
    DynObjectCast,
    VTableEntry,
    DynDispatchVTableEntry,
    MacroExpansion,
    ConstBody,
    CoroutineBody,
    Assert,
    IndirectCall,
}

/// Traversal modes in which one call occurrence is semantically applicable.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CallAttributionRole {
    ErasureSite,
    CallSite,
}

/// One exact call edge and its policy-neutral call properties.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct CallOccurrenceEntity {
    key: CallOccurrenceKey,
    kind: CallKind,
    #[serde(deserialize_with = "deserialize_call_attribution")]
    applicable_attribution: Vec<CallAttributionRole>,
    requires_unsafe: bool,
    inside_builtin_unsafe: bool,
    opaque_target_description: Option<String>,
}

impl RowSchema for CallOccurrenceEntity {
    const ID: &'static str = "sniff-test.core.call-occurrence";
    const VERSION: u32 = 1;
}

impl EntitySchema for CallOccurrenceEntity {
    type Key = CallOccurrenceKey;

    fn key(&self) -> Self::Key {
        self.key
    }
}

impl CallOccurrenceEntity {
    #[must_use]
    pub(crate) fn new(
        key: CallOccurrenceKey,
        kind: CallKind,
        mut applicable_attribution: Vec<CallAttributionRole>,
        requires_unsafe: bool,
        inside_builtin_unsafe: bool,
        opaque_target_description: Option<String>,
    ) -> Self {
        canonicalize_call_attribution(&mut applicable_attribution);
        Self {
            key,
            kind,
            applicable_attribution,
            requires_unsafe,
            inside_builtin_unsafe,
            opaque_target_description,
        }
    }

    #[must_use]
    pub(crate) const fn key(&self) -> &CallOccurrenceKey {
        &self.key
    }

    #[must_use]
    pub(crate) const fn kind(&self) -> CallKind {
        self.kind
    }

    #[must_use]
    pub(crate) fn applicable_attribution(&self) -> &[CallAttributionRole] {
        &self.applicable_attribution
    }

    #[must_use]
    pub(crate) const fn requires_unsafe(&self) -> bool {
        self.requires_unsafe
    }

    #[must_use]
    pub(crate) const fn inside_builtin_unsafe(&self) -> bool {
        self.inside_builtin_unsafe
    }

    #[must_use]
    pub(crate) fn opaque_target_description(&self) -> Option<&str> {
        self.opaque_target_description.as_deref()
    }
}

fn canonicalize_call_attribution(attribution: &mut Vec<CallAttributionRole>) {
    attribution.sort_unstable();
    attribution.dedup();
}

fn deserialize_call_attribution<'de, D>(
    deserializer: D,
) -> Result<Vec<CallAttributionRole>, D::Error>
where
    D: Deserializer<'de>,
{
    let mut attribution = Vec::<CallAttributionRole>::deserialize(deserializer)?;
    canonicalize_call_attribution(&mut attribution);
    Ok(attribution)
}

/// Stable erased-callable identity used to join erasure and invocation sites.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(
    rename_all = "kebab-case",
    tag = "kind",
    content = "identity",
    deny_unknown_fields
)]
pub(crate) enum CallableKey {
    FnPointer(StableTypeHash),
    DynDispatch(StableDefPathHash),
}

/// One callable-erasure join key known to this artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct CallableKeyEntity {
    key: CallableKey,
}

impl RowSchema for CallableKeyEntity {
    const ID: &'static str = "sniff-test.core.callable-key";
    const VERSION: u32 = 1;
}

impl EntitySchema for CallableKeyEntity {
    type Key = CallableKey;

    fn key(&self) -> Self::Key {
        self.key
    }
}

impl CallableKeyEntity {
    #[must_use]
    pub(crate) const fn new(key: CallableKey) -> Self {
        Self { key }
    }

    #[must_use]
    pub(crate) const fn key(&self) -> &CallableKey {
        &self.key
    }
}

/// One source-level safety group which can own several runtime effects.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct SafetyEffectGroupEntity {
    key: SafetyEffectGroupKey,
}

impl RowSchema for SafetyEffectGroupEntity {
    const ID: &'static str = "sniff-test.core.safety-effect-group";
    const VERSION: u32 = 1;
}

impl EntitySchema for SafetyEffectGroupEntity {
    type Key = SafetyEffectGroupKey;

    fn key(&self) -> Self::Key {
        self.key
    }
}

impl SafetyEffectGroupEntity {
    #[must_use]
    pub(crate) const fn new(key: SafetyEffectGroupKey) -> Self {
        Self { key }
    }

    #[must_use]
    pub(crate) const fn key(&self) -> &SafetyEffectGroupKey {
        &self.key
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
    /// Explicitly connects an owned body to its callable metadata.
    FunctionDefinesCallable,
    "sniff-test.core.function-defines-callable",
    FunctionEntity,
    CallableEntity
);
empty_relation!(
    /// Connects an owned body to one artifact-local source call site.
    FunctionOwnsCallSite,
    "sniff-test.core.function-owns-call-site",
    FunctionEntity,
    CallSiteEntity
);
empty_relation!(
    /// Associates a source call site with one resolved or structural edge.
    CallSiteHasOccurrence,
    "sniff-test.core.call-site-has-occurrence",
    CallSiteEntity,
    CallOccurrenceEntity
);
empty_relation!(
    /// Connects an owned body to one artifact-local safety effect group.
    FunctionOwnsSafetyEffectGroup,
    "sniff-test.core.function-owns-safety-effect-group",
    FunctionEntity,
    SafetyEffectGroupEntity
);
empty_relation!(
    /// Places one call occurrence in its source-level safety effect group.
    CallOccurrenceInSafetyEffectGroup,
    "sniff-test.core.call-occurrence-in-safety-effect-group",
    CallOccurrenceEntity,
    SafetyEffectGroupEntity
);

/// The semantic role played by callable metadata at one call occurrence.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CallTargetRole {
    Runtime,
    SourceContract,
    OpaqueTrait,
    OpaqueFunction,
}

/// Connects a call occurrence to a typed callable identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct CallOccurrenceTargetsCallable {
    role: CallTargetRole,
}

impl RowSchema for CallOccurrenceTargetsCallable {
    const ID: &'static str = "sniff-test.core.call-occurrence-targets-callable";
    const VERSION: u32 = 1;
}

impl RelationSchema for CallOccurrenceTargetsCallable {
    type From = CallOccurrenceEntity;
    type To = CallableEntity;
}

impl CallOccurrenceTargetsCallable {
    #[must_use]
    pub(crate) const fn new(role: CallTargetRole) -> Self {
        Self { role }
    }

    #[must_use]
    pub(crate) const fn role(&self) -> CallTargetRole {
        self.role
    }
}

empty_relation!(
    /// Associates one call occurrence with one erased-callable join key.
    /// Applicability is owned exclusively by `CallOccurrenceEntity`.
    CallOccurrenceHasCallableKey,
    "sniff-test.core.call-occurrence-has-callable-key",
    CallOccurrenceEntity,
    CallableKeyEntity
);

/// Which verified source representation an anchor has for a call occurrence.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CallSourceAnchorRole {
    Presentation,
    Expanded,
    Callee,
}

/// Connects a call occurrence to a verified source anchor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct CallOccurrenceHasSourceAnchor {
    role: CallSourceAnchorRole,
}

impl RowSchema for CallOccurrenceHasSourceAnchor {
    const ID: &'static str = "sniff-test.core.call-occurrence-has-source-anchor";
    const VERSION: u32 = 1;
}

impl RelationSchema for CallOccurrenceHasSourceAnchor {
    type From = CallOccurrenceEntity;
    type To = SourceAnchorEntity;
}

impl CallOccurrenceHasSourceAnchor {
    #[must_use]
    pub(crate) const fn new(role: CallSourceAnchorRole) -> Self {
        Self { role }
    }

    #[must_use]
    pub(crate) const fn role(&self) -> CallSourceAnchorRole {
        self.role
    }
}

/// Occurrence-relative identity of one ordered call macro-expansion frame.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct CallMacroExpansionKey {
    occurrence: CallOccurrenceKey,
    depth: u32,
}

impl CallMacroExpansionKey {
    #[must_use]
    pub(crate) const fn new(occurrence: CallOccurrenceKey, depth: u32) -> Self {
        Self { occurrence, depth }
    }

    #[must_use]
    pub(crate) const fn occurrence(&self) -> &CallOccurrenceKey {
        &self.occurrence
    }

    #[must_use]
    pub(crate) const fn depth(&self) -> u32 {
        self.depth
    }
}

/// One ordered macro-expansion frame that produced a call occurrence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct CallMacroExpansionEntity {
    key: CallMacroExpansionKey,
    expansion_hash: StableExpansionHash,
    macro_definition: StableDefPathHash,
    display_path: String,
}

impl RowSchema for CallMacroExpansionEntity {
    const ID: &'static str = "sniff-test.core.call-macro-expansion";
    const VERSION: u32 = 2;
}

impl EntitySchema for CallMacroExpansionEntity {
    type Key = CallMacroExpansionKey;

    fn key(&self) -> Self::Key {
        self.key
    }
}

impl CallMacroExpansionEntity {
    #[must_use]
    pub(crate) fn new(
        key: CallMacroExpansionKey,
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
    pub(crate) const fn key(&self) -> &CallMacroExpansionKey {
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
    /// Starts an occurrence-specific macro path at its owning function body.
    FunctionEntersCallMacroExpansion,
    "sniff-test.core.function-enters-call-macro-expansion",
    FunctionEntity,
    CallMacroExpansionEntity
);
empty_relation!(
    /// Connects adjacent outer-to-inner call macro-expansion frames.
    CallMacroExpansionEntersCallMacroExpansion,
    "sniff-test.core.call-macro-expansion-enters-call-macro-expansion",
    CallMacroExpansionEntity,
    CallMacroExpansionEntity
);
empty_relation!(
    /// Terminates an ordered call macro path at its semantic occurrence.
    CallMacroExpansionProducesCallOccurrence,
    "sniff-test.core.call-macro-expansion-produces-call-occurrence",
    CallMacroExpansionEntity,
    CallOccurrenceEntity
);
empty_relation!(
    /// Connects a call macro-expansion frame to its verified invocation anchor.
    CallMacroExpansionHasCallsite,
    "sniff-test.core.call-macro-expansion-has-callsite",
    CallMacroExpansionEntity,
    SourceAnchorEntity
);

pub(super) fn register<C: ?Sized>(
    registry: &mut super::super::pack::AnalysisRegistry<C>,
) -> Result<(), super::super::pack::PackRegistrationError> {
    registry.register_entity::<CallableEntity>()?;
    registry.register_entity::<CallSiteEntity>()?;
    registry.register_entity::<CallOccurrenceEntity>()?;
    registry.register_entity::<CallableKeyEntity>()?;
    registry.register_entity::<SafetyEffectGroupEntity>()?;
    registry.register_entity::<CallMacroExpansionEntity>()?;
    registry.register_relation::<FunctionDefinesCallable>()?;
    registry.register_relation::<FunctionOwnsCallSite>()?;
    registry.register_relation::<CallSiteHasOccurrence>()?;
    registry.register_relation::<CallOccurrenceTargetsCallable>()?;
    registry.register_relation::<CallOccurrenceHasCallableKey>()?;
    registry.register_relation::<FunctionOwnsSafetyEffectGroup>()?;
    registry.register_relation::<CallOccurrenceInSafetyEffectGroup>()?;
    registry.register_relation::<CallOccurrenceHasSourceAnchor>()?;
    registry.register_relation::<FunctionEntersCallMacroExpansion>()?;
    registry.register_relation::<CallMacroExpansionEntersCallMacroExpansion>()?;
    registry.register_relation::<CallMacroExpansionProducesCallOccurrence>()?;
    registry.register_relation::<CallMacroExpansionHasCallsite>()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::{CoreProgramPack, FunctionEntity, FunctionKey, SourceAnchorEntity};
    use super::{
        CallAttributionRole, CallKind, CallMacroExpansionEntersCallMacroExpansion,
        CallMacroExpansionEntity, CallMacroExpansionHasCallsite, CallMacroExpansionKey,
        CallMacroExpansionProducesCallOccurrence, CallOccurrenceEntity,
        CallOccurrenceHasCallableKey, CallOccurrenceHasSourceAnchor,
        CallOccurrenceInSafetyEffectGroup, CallOccurrenceKey, CallOccurrenceTargetsCallable,
        CallSiteEntity, CallSiteHasOccurrence, CallSiteKey, CallSourceAnchorRole, CallTargetRole,
        CallableEntity, CallableKey, CallableKeyEntity, FunctionDefinesCallable,
        FunctionEntersCallMacroExpansion, FunctionOwnsCallSite, FunctionOwnsSafetyEffectGroup,
        SafetyEffectGroupEntity, SafetyEffectGroupKey,
    };
    use crate::analysis::facts::pack::AnalysisRegistry;
    use crate::analysis::facts::schema::RowSchema;
    use crate::namespace::{
        StableDefPathHash, StableExpansionHash, StableInstanceHash, StableTypeHash,
    };

    fn definition(value: &str) -> StableDefPathHash {
        serde_json::from_str(&format!("\"{value}\"")).expect("valid definition hash")
    }

    fn expansion(value: &str) -> StableExpansionHash {
        serde_json::from_str(&format!("\"{value}\"")).expect("valid expansion hash")
    }

    fn instance(value: &str) -> StableInstanceHash {
        serde_json::from_str(&format!("\"{value}\"")).expect("valid instance hash")
    }

    fn type_hash(value: &str) -> StableTypeHash {
        serde_json::from_str(&format!("\"{value}\"")).expect("valid type hash")
    }

    fn exact_function() -> FunctionKey {
        FunctionKey::new(
            definition("00000000000000010000000000000002"),
            Some(instance("00000000000000030000000000000004")),
        )
    }

    #[test]
    fn callable_key_rejects_unknown_envelope_fields() {
        assert!(
            serde_json::from_value::<CallableKey>(json!({
                "kind": "fn-pointer",
                "identity": "00000000000000010000000000000002",
                "unexpected": true,
            }))
            .is_err()
        );
    }

    #[test]
    fn topology_keys_retain_exact_instance_and_artifact_local_grouping() {
        let owner = exact_function();
        let callable = CallableEntity::new(
            owner,
            "dependency::generic::<Local>",
            true,
            true,
            true,
            false,
            vec![
                String::from("dependency::generic"),
                String::from("dependency::generic::<Local>"),
                String::from("dependency::generic"),
            ],
        );
        let site = CallSiteEntity::new(CallSiteKey::new(owner, 7));
        let first = CallOccurrenceEntity::new(
            CallOccurrenceKey::new(owner, 11),
            CallKind::IndirectCall,
            vec![
                CallAttributionRole::CallSite,
                CallAttributionRole::ErasureSite,
                CallAttributionRole::CallSite,
            ],
            true,
            false,
            Some(String::from("indirect function-pointer call")),
        );
        let second = CallOccurrenceEntity::new(
            CallOccurrenceKey::new(owner, 12),
            CallKind::FnPointerCallTarget,
            vec![CallAttributionRole::CallSite],
            true,
            false,
            None,
        );
        let group = SafetyEffectGroupEntity::new(SafetyEffectGroupKey::new(owner, 5));

        assert_eq!(callable.key(), &owner);
        assert_eq!(callable.key().instance(), owner.instance());
        assert_eq!(callable.display_path(), "dependency::generic::<Local>");
        assert!(callable.is_unsafe());
        assert!(callable.is_exported());
        assert!(callable.has_rust_body());
        assert!(!callable.is_foreign());
        assert_eq!(
            callable.namespace_candidates(),
            &["dependency::generic", "dependency::generic::<Local>"]
        );
        assert_eq!(site.key().owner(), &owner);
        assert_eq!(site.key().local_id(), 7);
        assert_ne!(
            *site.key(),
            CallSiteKey::new(
                FunctionKey::new(
                    definition("00000000000000010000000000000002"),
                    Some(instance("0000000000000009000000000000000a")),
                ),
                7,
            )
        );
        assert_eq!(first.key().owner(), second.key().owner());
        assert_ne!(first.key(), second.key());
        assert_eq!(first.kind(), CallKind::IndirectCall);
        assert_eq!(
            first.applicable_attribution(),
            &[
                CallAttributionRole::ErasureSite,
                CallAttributionRole::CallSite,
            ]
        );
        assert!(first.requires_unsafe());
        assert!(!first.inside_builtin_unsafe());
        assert_eq!(
            first.opaque_target_description(),
            Some("indirect function-pointer call")
        );
        assert_eq!(group.key().owner(), &owner);
        assert_eq!(group.key().local_id(), 5);
    }

    #[test]
    fn target_attribution_anchor_and_macro_roles_are_typed() {
        assert_eq!(
            serde_json::to_value([
                CallTargetRole::Runtime,
                CallTargetRole::SourceContract,
                CallTargetRole::OpaqueTrait,
                CallTargetRole::OpaqueFunction,
            ])
            .unwrap(),
            json!([
                "runtime",
                "source-contract",
                "opaque-trait",
                "opaque-function"
            ])
        );
        assert_eq!(
            CallOccurrenceTargetsCallable::new(CallTargetRole::SourceContract).role(),
            CallTargetRole::SourceContract
        );
        assert_eq!(
            serde_json::to_value(CallOccurrenceHasCallableKey::new()).unwrap(),
            json!({})
        );
        assert_eq!(
            CallOccurrenceHasSourceAnchor::new(CallSourceAnchorRole::Callee).role(),
            CallSourceAnchorRole::Callee
        );

        let occurrence = CallOccurrenceKey::new(exact_function(), 9);
        let frame = CallMacroExpansionEntity::new(
            CallMacroExpansionKey::new(occurrence, 2),
            expansion("00000000000000070000000000000008"),
            definition("00000000000000050000000000000006"),
            "dependency::call_macro",
        );
        assert_eq!(frame.key().occurrence(), &occurrence);
        assert_eq!(frame.key().depth(), 2);
        assert_eq!(
            frame.macro_definition(),
            definition("00000000000000050000000000000006")
        );
        assert_eq!(
            frame.expansion_hash(),
            expansion("00000000000000070000000000000008")
        );
        assert_eq!(frame.display_path(), "dependency::call_macro");
        assert_eq!(CallMacroExpansionEntity::VERSION, 2);
        let mut missing_identity = serde_json::to_value(&frame).unwrap();
        missing_identity
            .as_object_mut()
            .unwrap()
            .remove("expansion-hash");
        assert!(serde_json::from_value::<CallMacroExpansionEntity>(missing_identity).is_err());
    }

    #[test]
    fn call_kind_canonically_covers_every_reachability_variant() {
        let kinds = [
            CallKind::DirectCall,
            CallKind::TailCall,
            CallKind::FnPointerReify,
            CallKind::ClosureFnPointerReify,
            CallKind::FnPointerCallTarget,
            CallKind::DynObjectCast,
            CallKind::VTableEntry,
            CallKind::DynDispatchVTableEntry,
            CallKind::MacroExpansion,
            CallKind::ConstBody,
            CallKind::CoroutineBody,
            CallKind::Assert,
            CallKind::IndirectCall,
        ];
        assert_eq!(
            serde_json::to_value(kinds).unwrap(),
            json!([
                "direct-call",
                "tail-call",
                "fn-pointer-reify",
                "closure-fn-pointer-reify",
                "fn-pointer-call-target",
                "dyn-object-cast",
                "v-table-entry",
                "dyn-dispatch-v-table-entry",
                "macro-expansion",
                "const-body",
                "coroutine-body",
                "assert",
                "indirect-call"
            ])
        );
    }

    #[test]
    fn topology_rows_have_canonical_strict_serde() {
        let owner = exact_function();
        let callable = CallableEntity::new(
            owner,
            "dependency::generic::<Local>",
            false,
            true,
            true,
            false,
            vec![
                String::from("z::candidate"),
                String::from("a::candidate"),
                String::from("a::candidate"),
            ],
        );
        let expected = json!({
            "key": {
                "definition": "00000000000000010000000000000002",
                "instance": "00000000000000030000000000000004"
            },
            "display-path": "dependency::generic::<Local>",
            "is-unsafe": false,
            "is-exported": true,
            "has-rust-body": true,
            "is-foreign": false,
            "namespace-candidates": ["a::candidate", "z::candidate"]
        });
        assert_eq!(serde_json::to_value(&callable).unwrap(), expected);
        let mut unknown = serde_json::to_value(&callable).unwrap();
        unknown
            .as_object_mut()
            .unwrap()
            .insert(String::from("unknown"), json!(true));
        assert!(serde_json::from_value::<CallableEntity>(unknown).is_err());

        let mut noncanonical = serde_json::to_value(&callable).unwrap();
        noncanonical["namespace-candidates"] =
            json!(["z::candidate", "a::candidate", "z::candidate"]);
        let decoded: CallableEntity = serde_json::from_value(noncanonical).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), expected);

        let callable_key = CallableKeyEntity::new(CallableKey::FnPointer(type_hash(
            "00000000000000070000000000000008",
        )));
        assert_eq!(
            serde_json::to_value(callable_key).unwrap(),
            json!({
                "key": {
                    "kind": "fn-pointer",
                    "identity": "00000000000000070000000000000008"
                }
            })
        );

        let direct: CallOccurrenceEntity = serde_json::from_value(json!({
            "key": {
                "owner": {
                    "definition": "00000000000000010000000000000002",
                    "instance": "00000000000000030000000000000004"
                },
                "local-id": 3
            },
            "kind": "direct-call",
            "applicable-attribution": ["call-site", "erasure-site", "call-site"],
            "requires-unsafe": false,
            "inside-builtin-unsafe": false,
            "opaque-target-description": null
        }))
        .unwrap();
        assert_eq!(
            direct.applicable_attribution(),
            &[
                CallAttributionRole::ErasureSite,
                CallAttributionRole::CallSite,
            ]
        );
        assert_eq!(
            serde_json::to_value(direct).unwrap()["applicable-attribution"],
            json!(["erasure-site", "call-site"])
        );
    }

    #[test]
    fn core_program_pack_registers_complete_call_topology_with_exact_endpoints() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CoreProgramPack).unwrap();

        for (entity, version) in [
            (CallableEntity::ID, 1),
            (CallSiteEntity::ID, 1),
            (CallOccurrenceEntity::ID, 1),
            (CallableKeyEntity::ID, 1),
            (SafetyEffectGroupEntity::ID, 1),
            (CallMacroExpansionEntity::ID, 2),
        ] {
            let descriptor = registry
                .schemas()
                .descriptor(&entity.parse().unwrap())
                .unwrap_or_else(|| panic!("missing entity {entity}"));
            assert_eq!(descriptor.version(), version);
        }

        assert_endpoints::<FunctionDefinesCallable>(
            &registry,
            FunctionEntity::ID,
            CallableEntity::ID,
        );
        assert_endpoints::<FunctionOwnsCallSite>(&registry, FunctionEntity::ID, CallSiteEntity::ID);
        assert_endpoints::<CallSiteHasOccurrence>(
            &registry,
            CallSiteEntity::ID,
            CallOccurrenceEntity::ID,
        );
        assert_endpoints::<CallOccurrenceTargetsCallable>(
            &registry,
            CallOccurrenceEntity::ID,
            CallableEntity::ID,
        );
        assert_endpoints::<CallOccurrenceHasCallableKey>(
            &registry,
            CallOccurrenceEntity::ID,
            CallableKeyEntity::ID,
        );
        assert_endpoints::<FunctionOwnsSafetyEffectGroup>(
            &registry,
            FunctionEntity::ID,
            SafetyEffectGroupEntity::ID,
        );
        assert_endpoints::<CallOccurrenceInSafetyEffectGroup>(
            &registry,
            CallOccurrenceEntity::ID,
            SafetyEffectGroupEntity::ID,
        );
        assert_endpoints::<CallOccurrenceHasSourceAnchor>(
            &registry,
            CallOccurrenceEntity::ID,
            SourceAnchorEntity::ID,
        );
        assert_endpoints::<FunctionEntersCallMacroExpansion>(
            &registry,
            FunctionEntity::ID,
            CallMacroExpansionEntity::ID,
        );
        assert_endpoints::<CallMacroExpansionEntersCallMacroExpansion>(
            &registry,
            CallMacroExpansionEntity::ID,
            CallMacroExpansionEntity::ID,
        );
        assert_endpoints::<CallMacroExpansionProducesCallOccurrence>(
            &registry,
            CallMacroExpansionEntity::ID,
            CallOccurrenceEntity::ID,
        );
        assert_endpoints::<CallMacroExpansionHasCallsite>(
            &registry,
            CallMacroExpansionEntity::ID,
            SourceAnchorEntity::ID,
        );
    }

    fn assert_endpoints<R: crate::analysis::facts::schema::RelationSchema>(
        registry: &AnalysisRegistry<()>,
        from: &str,
        to: &str,
    ) {
        let descriptor = registry
            .schemas()
            .descriptor(&R::ID.parse().unwrap())
            .expect("relation is registered");
        let endpoints = descriptor.relation_endpoints().expect("typed endpoints");
        assert_eq!(descriptor.version(), 1);
        assert_eq!(endpoints.from.as_str(), from);
        assert_eq!(endpoints.to.as_str(), to);
    }
}
