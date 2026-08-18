//! Typed schema identities and row contracts for the open fact database.
//!
//! Analysis code stays generic over these traits and typed entity references.
//! Only the persistence boundary erases a schema to its stable string ID.

use std::any::type_name;
use std::borrow::Borrow;
use std::cmp::Ordering;
use std::fmt::{self, Debug, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::str::FromStr;

use serde::de::{DeserializeOwned, Error as _};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use super::encoded::{EntityRef, RowRef};

/// Why a stable infrastructure identifier was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StableIdError {
    Empty,
    EmptySegment { index: usize },
    InvalidCharacter { index: usize, character: char },
    InvalidSegmentBoundary { index: usize, character: char },
}

impl Display for StableIdError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("identifier must not be empty"),
            Self::EmptySegment { index } => {
                write!(formatter, "identifier has an empty segment at byte {index}")
            }
            Self::InvalidCharacter { index, character } => write!(
                formatter,
                "identifier contains invalid character {character:?} at byte {index}"
            ),
            Self::InvalidSegmentBoundary { index, character } => write!(
                formatter,
                "identifier segment cannot start or end with {character:?} at byte {index}"
            ),
        }
    }
}

impl std::error::Error for StableIdError {}

fn validate_stable_id(value: &str) -> Result<(), StableIdError> {
    if value.is_empty() {
        return Err(StableIdError::Empty);
    }

    let mut segment_start = 0;
    for (index, character) in value.char_indices() {
        if character == '.' {
            if index == segment_start {
                return Err(StableIdError::EmptySegment { index });
            }
            let previous_index = index - 1;
            let previous = value.as_bytes()[previous_index] as char;
            if !previous.is_ascii_lowercase() && !previous.is_ascii_digit() {
                return Err(StableIdError::InvalidSegmentBoundary {
                    index: previous_index,
                    character: previous,
                });
            }
            segment_start = index + 1;
            continue;
        }

        if !character.is_ascii_lowercase()
            && !character.is_ascii_digit()
            && character != '-'
            && character != '_'
        {
            return Err(StableIdError::InvalidCharacter { index, character });
        }
        if index == segment_start && !character.is_ascii_lowercase() && !character.is_ascii_digit()
        {
            return Err(StableIdError::InvalidSegmentBoundary { index, character });
        }
    }

    if segment_start == value.len() {
        return Err(StableIdError::EmptySegment {
            index: value.len() - 1,
        });
    }
    let final_index = value.len() - 1;
    let final_character = value.as_bytes()[final_index] as char;
    if !final_character.is_ascii_lowercase() && !final_character.is_ascii_digit() {
        return Err(StableIdError::InvalidSegmentBoundary {
            index: final_index,
            character: final_character,
        });
    }
    Ok(())
}

macro_rules! stable_id_type {
    ($(#[$meta:meta])* $name:ident, $label:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub(crate) struct $name(String);

        impl $name {
            pub(crate) fn new(value: impl Into<String>) -> Result<Self, StableIdError> {
                let value = value.into();
                validate_stable_id(&value)?;
                Ok(Self(value))
            }

            #[must_use]
            pub(crate) fn as_str(&self) -> &str {
                &self.0
            }

        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl Borrow<str> for $name {
            fn borrow(&self) -> &str {
                self.as_str()
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl FromStr for $name {
            type Err = StableIdError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl TryFrom<String> for $name {
            type Error = StableIdError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = StableIdError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(|error| {
                    D::Error::custom(format_args!("invalid {}: {error}", $label))
                })
            }
        }
    };
}

stable_id_type!(
    /// Stable semantic identity of one independently versioned row schema.
    SchemaId,
    "schema ID"
);

stable_id_type!(
    /// Stable identity of an artifact or evaluation pass.
    PassId,
    "pass ID"
);

/// Typed row contract shared by every registered schema.
pub(crate) trait RowSchema: Serialize + DeserializeOwned + Clone + 'static {
    /// Stable semantic identity, independent of the Rust type or module name.
    const ID: &'static str;
    /// Independently bumped encoded-shape version. Version zero is invalid.
    const VERSION: u32;
}

/// A semantic object referenced by facts or relations.
pub(crate) trait EntitySchema: RowSchema {
    /// Canonically serializable identity used before numeric row assignment.
    type Key: Ord + Clone + Serialize + DeserializeOwned + 'static;

    fn key(&self) -> Self::Key;
}

/// A policy-neutral statement about one or more entities.
pub(crate) trait FactSchema: RowSchema {}

/// A directed, typed provenance edge between two entity schemas.
pub(crate) trait RelationSchema: RowSchema {
    type From: EntitySchema;
    type To: EntitySchema;
}

/// A typed directed edge derived while composing exact artifact generations.
///
/// Composition relations are evaluation-root-scoped and never enter artifact
/// caches. The separate marker lets the registry enforce that stage boundary
/// while reusing the relation's typed endpoints and stable row schema.
pub(crate) trait CompositionRelationSchema: RelationSchema {}

/// An open typed condition that may be referenced by obligations.
pub(crate) trait RequirementSchema: RowSchema {}

/// A root-specific intermediate row produced and consumed by evaluation rules.
///
/// Derived rows never belong to artifact caches and do not imply that a
/// renderer exists. They carry obligations, evidence matches, completeness
/// outcomes, or other typed state between rules in one evaluation DAG.
pub(crate) trait DerivedSchema: RowSchema {}

/// An open typed evaluated outcome suitable for a registered renderer.
pub(crate) trait IssueSchema: RowSchema {}

/// Symbolic identity of a typed row before deterministic row assignment.
///
/// The identity is the row's complete canonical encoded representation. It is
/// branded by `S`, so equal bytes from two schemas cannot be mixed or compared.
/// Symbolic handles are collection-only and deliberately do not implement
/// serde; persisted references use [`RowId`] or erased [`RowRef`] values after
/// finalization.
pub(crate) struct RowHandle<S: RowSchema> {
    canonical: Vec<u8>,
    marker: PhantomData<fn() -> S>,
}

impl<S: RowSchema> RowHandle<S> {
    /// Creates the stable symbolic identity of one typed row.
    pub(crate) fn from_row(row: &S) -> Result<Self, SchemaCodecError> {
        let encoded = encode_row(row)?;
        let canonical = canonical_json_bytes(S::ID, &encoded)?;
        Ok(Self {
            canonical,
            marker: PhantomData,
        })
    }

    /// Canonical identity consumed by infrastructure during finalization.
    #[must_use]
    pub(super) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
}

impl<S: RowSchema> Clone for RowHandle<S> {
    fn clone(&self) -> Self {
        Self {
            canonical: self.canonical.clone(),
            marker: PhantomData,
        }
    }
}

impl<S: RowSchema> PartialEq for RowHandle<S> {
    fn eq(&self, other: &Self) -> bool {
        self.canonical == other.canonical
    }
}

impl<S: RowSchema> Eq for RowHandle<S> {}

impl<S: RowSchema> PartialOrd for RowHandle<S> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<S: RowSchema> Ord for RowHandle<S> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.canonical.cmp(&other.canonical)
    }
}

impl<S: RowSchema> Hash for RowHandle<S> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.canonical.hash(state);
    }
}

impl<S: RowSchema> Debug for RowHandle<S> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RowHandle")
            .field("schema", &S::ID)
            .field("canonical", &String::from_utf8_lossy(&self.canonical))
            .finish()
    }
}

/// Typed finalized row ID. Numeric IDs are local to one artifact database.
///
/// Only fact-database infrastructure can construct an ID directly. Analysis
/// packs receive IDs from validated typed views and retain the schema brand in
/// memory; heterogeneous infrastructure erases them explicitly with
/// [`RowId::erase`].
pub(crate) struct RowId<S: RowSchema> {
    index: u32,
    marker: PhantomData<fn() -> S>,
}

impl<S: RowSchema> RowId<S> {
    /// Constructs an ID after infrastructure has assigned or validated `index`.
    #[must_use]
    pub(super) const fn new(index: u32) -> Self {
        Self {
            index,
            marker: PhantomData,
        }
    }

    #[must_use]
    pub(crate) const fn row(self) -> u32 {
        self.index
    }

    /// Erases the type brand at a heterogeneous infrastructure boundary.
    #[must_use]
    pub(crate) fn erase(self) -> RowRef {
        let schema =
            SchemaId::new(S::ID).expect("a RowId can only be created for a registered schema");
        RowRef {
            schema,
            row: self.index,
        }
    }
}

impl<S: RowSchema> Copy for RowId<S> {}

#[allow(
    clippy::expl_impl_clone_on_copy,
    reason = "a derived impl would require the row type itself to be Copy"
)]
impl<S: RowSchema> Clone for RowId<S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<S: RowSchema> PartialEq for RowId<S> {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index
    }
}

impl<S: RowSchema> Eq for RowId<S> {}

impl<S: RowSchema> PartialOrd for RowId<S> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<S: RowSchema> Ord for RowId<S> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.index.cmp(&other.index)
    }
}

impl<S: RowSchema> Hash for RowId<S> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.index.hash(state);
    }
}

impl<S: RowSchema> Debug for RowId<S> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple(type_name::<Self>())
            .field(&self.index)
            .finish()
    }
}

impl<S: RowSchema> Serialize for RowId<S> {
    fn serialize<T>(&self, serializer: T) -> Result<T::Ok, T::Error>
    where
        T: Serializer,
    {
        serializer.serialize_u32(self.index)
    }
}

impl<'de, S: RowSchema> Deserialize<'de> for RowId<S> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        u32::deserialize(deserializer).map(Self::new)
    }
}

/// Symbolic typed entity reference used before deterministic row assignment.
pub(crate) struct EntityHandle<E: EntitySchema> {
    key: E::Key,
    marker: PhantomData<fn() -> E>,
}

impl<E: EntitySchema> EntityHandle<E> {
    #[must_use]
    pub(crate) fn new(key: E::Key) -> Self {
        Self {
            key,
            marker: PhantomData,
        }
    }

    #[must_use]
    pub(crate) fn from_entity(entity: &E) -> Self {
        Self::new(entity.key())
    }

    #[must_use]
    pub(crate) fn key(&self) -> &E::Key {
        &self.key
    }

    #[must_use]
    pub(crate) fn into_key(self) -> E::Key {
        self.key
    }
}

impl<E: EntitySchema> Clone for EntityHandle<E> {
    fn clone(&self) -> Self {
        Self::new(self.key.clone())
    }
}

impl<E: EntitySchema> PartialEq for EntityHandle<E> {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl<E: EntitySchema> Eq for EntityHandle<E> {}

impl<E: EntitySchema> PartialOrd for EntityHandle<E> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<E: EntitySchema> Ord for EntityHandle<E> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key.cmp(&other.key)
    }
}

impl<E> Hash for EntityHandle<E>
where
    E: EntitySchema,
    E::Key: Hash,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.key.hash(state);
    }
}

impl<E> Debug for EntityHandle<E>
where
    E: EntitySchema,
    E::Key: Debug,
{
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EntityHandle")
            .field("schema", &E::ID)
            .field("key", &self.key)
            .finish()
    }
}

/// Typed finalized row ID. Numeric IDs are artifact-local.
pub(crate) struct EntityId<E: EntitySchema> {
    index: u32,
    marker: PhantomData<fn() -> E>,
}

impl<E: EntitySchema> EntityId<E> {
    #[must_use]
    pub(super) const fn new(index: u32) -> Self {
        Self {
            index,
            marker: PhantomData,
        }
    }

    #[must_use]
    pub(crate) const fn row(self) -> u32 {
        self.index
    }

    /// Erases a finalized ID after its schema has been registered.
    #[must_use]
    pub(crate) fn erase(self) -> EntityRef {
        let schema =
            SchemaId::new(E::ID).expect("an EntityId can only be created for a registered schema");
        EntityRef {
            schema,
            row: self.index,
        }
    }
}

impl<E: EntitySchema> Copy for EntityId<E> {}

#[allow(
    clippy::expl_impl_clone_on_copy,
    reason = "a derived impl would require the entity row type itself to be Copy"
)]
impl<E: EntitySchema> Clone for EntityId<E> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<E: EntitySchema> PartialEq for EntityId<E> {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index
    }
}

impl<E: EntitySchema> Eq for EntityId<E> {}

impl<E: EntitySchema> PartialOrd for EntityId<E> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<E: EntitySchema> Ord for EntityId<E> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.index.cmp(&other.index)
    }
}

impl<E: EntitySchema> Hash for EntityId<E> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.index.hash(state);
    }
}

impl<E: EntitySchema> Debug for EntityId<E> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple(type_name::<Self>())
            .field(&self.index)
            .finish()
    }
}

impl<E: EntitySchema> Serialize for EntityId<E> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u32(self.index)
    }
}

impl<'de, E: EntitySchema> Deserialize<'de> for EntityId<E> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        u32::deserialize(deserializer).map(Self::new)
    }
}

/// Failure while crossing the typed/JSON persistence boundary.
#[derive(Debug)]
pub(crate) enum SchemaCodecError {
    Serde {
        schema: String,
        operation: &'static str,
        source: serde_json::Error,
    },
    NonCanonicalRow {
        schema: String,
    },
}

impl SchemaCodecError {
    fn serde(
        schema: impl Into<String>,
        operation: &'static str,
        source: serde_json::Error,
    ) -> Self {
        Self::Serde {
            schema: schema.into(),
            operation,
            source,
        }
    }
}

impl Display for SchemaCodecError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serde {
                schema,
                operation,
                source,
            } => write!(
                formatter,
                "failed to {operation} for schema {schema}: {source}"
            ),
            Self::NonCanonicalRow { schema } => write!(
                formatter,
                "encoded row for schema {schema} contains data not represented by its registered type"
            ),
        }
    }
}

impl std::error::Error for SchemaCodecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Serde { source, .. } => Some(source),
            Self::NonCanonicalRow { .. } => None,
        }
    }
}

/// Encodes one typed row into canonical JSON.
pub(crate) fn encode_row<S: RowSchema>(row: &S) -> Result<Value, SchemaCodecError> {
    encode_json(S::ID, "encode row", row)
}

/// Decodes one typed row from its erased JSON representation.
pub(crate) fn decode_row<S: RowSchema>(value: &Value) -> Result<S, SchemaCodecError> {
    serde_json::from_value(value.clone())
        .map_err(|source| SchemaCodecError::serde(S::ID, "decode row", source))
}

/// Validates and returns the canonical encoding of one registered row.
pub(crate) fn canonicalize_row<S: RowSchema>(value: &Value) -> Result<Value, SchemaCodecError> {
    let encoded = encode_row(&decode_row::<S>(value)?)?;
    let mut input = value.clone();
    canonicalize_json(&mut input);
    if input != encoded {
        return Err(SchemaCodecError::NonCanonicalRow {
            schema: S::ID.to_owned(),
        });
    }
    Ok(encoded)
}

/// Encodes an entity's stable key using the same canonical JSON rules as rows.
pub(crate) fn encode_entity_key<E: EntitySchema>(key: &E::Key) -> Result<Value, SchemaCodecError> {
    encode_json(E::ID, "encode entity key", key)
}

fn encode_json<T: Serialize + ?Sized>(
    schema: &str,
    operation: &'static str,
    value: &T,
) -> Result<Value, SchemaCodecError> {
    let mut encoded = serde_json::to_value(value)
        .map_err(|source| SchemaCodecError::serde(schema, operation, source))?;
    canonicalize_json(&mut encoded);
    Ok(encoded)
}

/// Recursively orders JSON object keys, including objects nested in arrays.
pub(crate) fn canonicalize_json(value: &mut Value) {
    match value {
        Value::Array(values) => {
            for value in values {
                canonicalize_json(value);
            }
        }
        Value::Object(object) => {
            let mut entries = std::mem::take(object).into_iter().collect::<Vec<_>>();
            for (_, value) in &mut entries {
                canonicalize_json(value);
            }
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            object.extend(entries);
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

/// Returns deterministic JSON bytes for sorting and duplicate detection.
pub(crate) fn canonical_json_bytes(
    schema: &str,
    value: &Value,
) -> Result<Vec<u8>, SchemaCodecError> {
    let mut value = value.clone();
    canonicalize_json(&mut value);
    serde_json::to_vec(&value)
        .map_err(|source| SchemaCodecError::serde(schema, "encode canonical JSON", source))
}

#[cfg(test)]
mod tests {
    use std::any::TypeId;

    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(Clone, Serialize, Deserialize)]
    struct SampleEntity {
        name: String,
    }

    impl RowSchema for SampleEntity {
        const ID: &'static str = "sample.core.entity";
        const VERSION: u32 = 1;
    }

    impl EntitySchema for SampleEntity {
        type Key = String;

        fn key(&self) -> Self::Key {
            self.name.clone()
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct SampleRequirement {
        predicate: Value,
    }

    impl RowSchema for SampleRequirement {
        const ID: &'static str = "sample.core.requirement";
        const VERSION: u32 = 1;
    }

    impl RequirementSchema for SampleRequirement {}

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct OtherRequirement {
        predicate: Value,
    }

    impl RowSchema for OtherRequirement {
        const ID: &'static str = "sample.other.requirement";
        const VERSION: u32 = 1;
    }

    impl RequirementSchema for OtherRequirement {}

    #[test]
    fn stable_ids_are_validated_and_serialize_as_strings() {
        let schema = SchemaId::new("sniff-test.core.function").expect("valid schema ID");
        let pass = PassId::new("sniff-test.panic.collect-mir").expect("valid pass ID");

        assert_eq!(schema.as_str(), "sniff-test.core.function");
        assert_eq!(
            serde_json::to_string(&schema).unwrap(),
            "\"sniff-test.core.function\""
        );
        assert_eq!(
            serde_json::from_str::<SchemaId>("\"sniff-test.core.function\"").unwrap(),
            schema
        );
        assert_eq!(pass.as_str(), "sniff-test.panic.collect-mir");
    }

    #[test]
    fn stable_ids_reject_noncanonical_spellings() {
        for invalid in [
            "",
            ".sample",
            "sample.",
            "sample..fact",
            "Sample.fact",
            "sample fact",
        ] {
            assert!(
                SchemaId::new(invalid).is_err(),
                "{invalid:?} must be rejected"
            );
        }
        assert!(serde_json::from_str::<PassId>("\"sample/pass\"").is_err());
    }

    #[test]
    fn typed_handles_compare_by_stable_key() {
        let first = EntityHandle::<SampleEntity>::new("a".to_owned());
        let second = EntityHandle::<SampleEntity>::from_entity(&SampleEntity {
            name: "b".to_owned(),
        });

        assert!(first < second);
        assert_eq!(first.key(), "a");
        assert_eq!(second.into_key(), "b");
    }

    #[test]
    fn typed_final_ids_erase_with_their_schema() {
        let id = EntityId::<SampleEntity>::new(7);
        let encoded = serde_json::to_string(&id).expect("serialize typed entity ID");

        assert_eq!(encoded, "7");
        assert_eq!(
            serde_json::from_str::<EntityId<SampleEntity>>(&encoded).unwrap(),
            id
        );
        assert_eq!(id.erase().schema.as_str(), SampleEntity::ID);
        assert_eq!(id.erase().row, 7);
    }

    #[test]
    fn symbolic_row_handles_use_canonical_row_identity() {
        let first = RowHandle::<SampleRequirement>::from_row(&SampleRequirement {
            predicate: serde_json::json!({"z": 2, "a": {"y": 1, "b": 0}}),
        })
        .expect("encode symbolic requirement identity");
        let same = RowHandle::<SampleRequirement>::from_row(&SampleRequirement {
            predicate: serde_json::json!({"a": {"b": 0, "y": 1}, "z": 2}),
        })
        .expect("encode equivalent symbolic requirement identity");
        let later = RowHandle::<SampleRequirement>::from_row(&SampleRequirement {
            predicate: serde_json::json!({"z": 3}),
        })
        .expect("encode distinct symbolic requirement identity");

        assert_eq!(first, same);
        assert!(first < later);
        assert_eq!(
            first.canonical_bytes(),
            br#"{"predicate":{"a":{"b":0,"y":1},"z":2}}"#
        );
        assert!(format!("{first:?}").contains(SampleRequirement::ID));
    }

    #[test]
    fn row_identity_is_branded_by_its_schema_type() {
        let sample = RowHandle::<SampleRequirement>::from_row(&SampleRequirement {
            predicate: serde_json::json!({"condition": true}),
        })
        .unwrap();
        let other = RowHandle::<OtherRequirement>::from_row(&OtherRequirement {
            predicate: serde_json::json!({"condition": true}),
        })
        .unwrap();

        assert_eq!(sample.canonical_bytes(), other.canonical_bytes());
        assert_ne!(
            TypeId::of::<RowHandle<SampleRequirement>>(),
            TypeId::of::<RowHandle<OtherRequirement>>()
        );
        assert_ne!(
            TypeId::of::<RowId<SampleRequirement>>(),
            TypeId::of::<RowId<OtherRequirement>>()
        );
    }

    #[test]
    fn finalized_row_ids_serialize_as_indices_and_erase_with_their_schema() {
        let id = RowId::<SampleRequirement>::new(11);
        let encoded = serde_json::to_string(&id).expect("serialize typed row ID");
        let decoded = serde_json::from_str::<RowId<SampleRequirement>>(&encoded)
            .expect("deserialize typed row ID");

        assert_eq!(encoded, "11");
        assert_eq!(decoded, id);
        assert_eq!(
            decoded.erase(),
            RowRef {
                schema: SchemaId::new(SampleRequirement::ID).unwrap(),
                row: 11,
            }
        );
        assert!(format!("{decoded:?}").contains("11"));
    }

    #[test]
    fn row_codec_canonicalizes_nested_object_keys() {
        let value = serde_json::json!({"z": {"b": 2, "a": 1}, "a": 0});
        let bytes = canonical_json_bytes(SampleEntity::ID, &value).expect("canonical JSON");

        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            r#"{"a":0,"z":{"a":1,"b":2}}"#
        );
    }
}
