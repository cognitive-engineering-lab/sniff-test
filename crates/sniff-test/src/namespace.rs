//! Canonical Rust namespace rendering for config and cache matching.
//!
//! Configuration patterns are matched against stable [`NamespaceCandidates`]
//! forms of a definition: the crate root, such as `serde`, the definition-site
//! path, such as `serde::de::from_str`, and for impl items the self-type path,
//! such as `alloc::vec::Vec::index`. The session-rendered display form is also
//! a match candidate. Rust crate names use underscores, not
//! package-name hyphens, so users should write `proc_macro2`, not `proc-macro2`.
//!
//! Cache identity uses [`StableDefPathHash`] instead of rendered paths:
//! pretty-printed paths differ between the defining crate's session and a
//! consumer's session (trait qualification, re-exports), while def path hashes
//! are read from crate metadata and agree by construction.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;

use rustc_data_structures::fingerprint::Fingerprint;
use rustc_data_structures::stable_hasher::{HashStable, StableHasher, ToStableHashKey};
use rustc_hir::def::DefKind;
use rustc_hir::def_id::DefId;
use rustc_middle::mono::MonoItem;
use rustc_middle::ty::{Instance, Ty, TyCtxt};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

// The driver runs one rustc session per process and the analysis is
// single-threaded, so `DefId`-keyed caches stay valid for the process
// lifetime. Rendering def paths is a hot cost: policy checks run per edge of
// every per-root traversal, and `def_path_str` re-pretty-prints each time.
thread_local! {
    static NAMESPACE_CACHE: RefCell<HashMap<DefId, String>> = RefCell::new(HashMap::new());
    static CANDIDATES_CACHE: RefCell<HashMap<DefId, NamespaceCandidates>> =
        RefCell::new(HashMap::new());
}

/// Session-independent identity for a definition.
///
/// Its serialized form is 32 hexadecimal digits: the stable crate id followed
/// by the item-local def-path hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StableDefPathHash(StableHash);

impl StableDefPathHash {
    #[must_use]
    pub fn from_def_id(tcx: TyCtxt<'_>, def_id: DefId) -> Self {
        let hash = tcx.def_path_hash(def_id);
        Self::from_parts(hash.stable_crate_id().as_u64(), hash.local_hash().as_u64())
    }

    #[must_use]
    pub const fn stable_crate_id(self) -> u64 {
        self.0.first
    }

    const fn from_parts(stable_crate_id: u64, local_hash: u64) -> Self {
        Self(StableHash::from_parts(stable_crate_id, local_hash))
    }
}

impl fmt::Display for StableDefPathHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Session-independent identity for one rustc function instance.
///
/// Unlike [`StableDefPathHash`], this distinguishes generic substitutions and
/// compiler-generated instance kinds such as shims. It deliberately uses
/// rustc's stable `MonoItem::Fn` key so cache identity matches rustc's own
/// monomorphization identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StableInstanceHash(StableHash);

impl StableInstanceHash {
    #[must_use]
    pub fn from_instance<'tcx>(tcx: TyCtxt<'tcx>, instance: Instance<'tcx>) -> Self {
        let fingerprint = tcx.with_stable_hashing_context(|mut hcx| {
            MonoItem::Fn(instance).to_stable_hash_key(&mut hcx)
        });
        Self::from_fingerprint(fingerprint)
    }

    fn from_fingerprint(fingerprint: Fingerprint) -> Self {
        let (first, second) = fingerprint.split();
        Self::from_parts(first.as_u64(), second.as_u64())
    }

    const fn from_parts(first: u64, second: u64) -> Self {
        Self(StableHash::from_parts(first, second))
    }
}

impl fmt::Display for StableInstanceHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Session-independent identity for one monomorphized Rust type.
///
/// Callable call-site attribution uses this for function-pointer signatures so
/// raw erasure and invocation facts can be matched after artifact IR is loaded
/// into a different compiler session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StableTypeHash(StableHash);

impl StableTypeHash {
    #[must_use]
    pub fn from_ty<'tcx>(tcx: TyCtxt<'tcx>, ty: Ty<'tcx>) -> Self {
        let fingerprint = tcx.with_stable_hashing_context(|mut hcx| {
            let mut hasher = StableHasher::new();
            ty.hash_stable(&mut hcx, &mut hasher);
            hasher.finish::<Fingerprint>()
        });
        Self(StableHash::from_fingerprint(fingerprint))
    }
}

impl fmt::Display for StableTypeHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct StableHash {
    first: u64,
    second: u64,
}

impl StableHash {
    const fn from_parts(first: u64, second: u64) -> Self {
        Self { first, second }
    }

    fn from_fingerprint(fingerprint: Fingerprint) -> Self {
        let (first, second) = fingerprint.split();
        Self::from_parts(first.as_u64(), second.as_u64())
    }

    fn from_hex(value: &str) -> Option<Self> {
        if value.len() != 32 || !value.is_ascii() {
            return None;
        }
        let (first, second) = value.split_at(16);
        Some(Self {
            first: u64::from_str_radix(first, 16).ok()?,
            second: u64::from_str_radix(second, 16).ok()?,
        })
    }
}

impl fmt::Display for StableHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:016x}{:016x}", self.first, self.second)
    }
}

impl Serialize for StableHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for StableHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_hex(&value).ok_or_else(|| {
            serde::de::Error::custom("stable hash must contain exactly 32 hexadecimal digits")
        })
    }
}

/// Namespace forms a definition can be matched against.
///
/// The crate, definition-site, and self-type forms are stable across compiler
/// sessions. `display` is rustc's session-rendered form.
#[derive(Debug, Clone)]
pub struct NamespaceCandidates {
    /// The defining crate root, such as `alloc`.
    pub crate_name: String,
    /// The definition-site path, such as `alloc::vec::{impl#5}::index`.
    pub def_site: String,
    /// The self-type path for impl items, such as `alloc::vec::Vec::index`.
    ///
    /// Only present when the self type is an ADT of the defining crate, so an
    /// `impl MyTrait for Vec<u8>` in a user crate never matches `alloc::**`.
    pub self_type: Option<String>,
    /// rustc's session-rendered pretty-printed form.
    pub display: String,
}

impl NamespaceCandidates {
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        [
            Some(self.crate_name.as_str()),
            Some(self.def_site.as_str()),
            self.self_type.as_deref(),
            Some(self.display.as_str()),
        ]
        .into_iter()
        .flatten()
    }
}

#[must_use]
pub fn namespace_candidates(tcx: TyCtxt<'_>, def_id: DefId) -> NamespaceCandidates {
    CANDIDATES_CACHE.with_borrow_mut(|cache| {
        cache
            .entry(def_id)
            .or_insert_with(|| {
                let crate_name = tcx.crate_name(def_id.krate).to_string();
                let def_site = format!(
                    "{crate_name}{}",
                    tcx.def_path(def_id).to_string_no_crate_verbose()
                );
                NamespaceCandidates {
                    self_type: impl_self_type_path(tcx, def_id, &crate_name),
                    display: canonical_namespace(tcx, def_id),
                    crate_name,
                    def_site,
                }
            })
            .clone()
    })
}

fn impl_self_type_path(tcx: TyCtxt<'_>, def_id: DefId, crate_name: &str) -> Option<String> {
    let parent = tcx.opt_parent(def_id)?;
    if !matches!(tcx.def_kind(parent), DefKind::Impl { .. }) {
        return None;
    }
    let adt = tcx
        .type_of(parent)
        .instantiate_identity()
        .skip_normalization()
        .ty_adt_def()
        .filter(|adt| adt.did().krate == def_id.krate)?;
    // Nameless defs (anonymous consts, closures) can be owned directly by an
    // impl; `item_name` ICEs on them.
    let name = tcx.opt_item_name(def_id)?;
    Some(format!(
        "{crate_name}{}::{}",
        tcx.def_path(adt.did()).to_string_no_crate_verbose(),
        name
    ))
}

#[must_use]
pub fn canonical_namespace(tcx: TyCtxt<'_>, def_id: DefId) -> String {
    NAMESPACE_CACHE.with_borrow_mut(|cache| {
        cache
            .entry(def_id)
            .or_insert_with(|| {
                let crate_name = tcx.crate_name(def_id.krate).to_string();
                canonicalize_def_path(&crate_name, &tcx.def_path_str(def_id))
            })
            .clone()
    })
}

fn canonicalize_def_path(crate_name: &str, path: &str) -> String {
    if path == crate_name
        || path
            .strip_prefix(crate_name)
            .is_some_and(|rest| rest.starts_with("::"))
        || path
            .strip_prefix('<')
            .and_then(|rest| rest.strip_prefix(crate_name))
            .is_some_and(|rest| rest.starts_with("::"))
    {
        path.to_owned()
    } else if let Some(path) = path.strip_prefix('<') {
        // Associated paths can start with the self type, so qualify that type
        // with the current crate when rustc gives us a local-style path.
        format!("<{crate_name}::{path}")
    } else {
        format!("{crate_name}::{path}")
    }
}

#[cfg(test)]
mod tests {
    use super::{StableDefPathHash, StableInstanceHash, canonicalize_def_path};

    #[test]
    fn stable_hashes_use_canonical_hex_for_display_and_serde() {
        let definition = StableDefPathHash::from_parts(0x1, 0x00ab_cdef);
        let instance = StableInstanceHash::from_parts(0x10, 0x00fe_dcba);

        assert_eq!(definition.to_string(), "00000000000000010000000000abcdef");
        assert_eq!(instance.to_string(), "00000000000000100000000000fedcba");

        let definition_json = serde_json::to_string(&definition).expect("serialize definition");
        let instance_json = serde_json::to_string(&instance).expect("serialize instance");

        assert_eq!(definition_json, format!("\"{definition}\""));
        assert_eq!(instance_json, format!("\"{instance}\""));
        assert_eq!(
            serde_json::from_str::<StableDefPathHash>(&definition_json)
                .expect("deserialize definition"),
            definition
        );
        assert_eq!(
            serde_json::from_str::<StableInstanceHash>(&instance_json)
                .expect("deserialize instance"),
            instance
        );
    }

    #[test]
    fn stable_hash_deserialization_rejects_malformed_hex() {
        let error = serde_json::from_str::<StableDefPathHash>("\"12\"")
            .expect_err("malformed hashes must be rejected");

        assert!(error.to_string().contains("32 hexadecimal digits"));
    }

    #[test]
    fn canonical_paths_include_crate_root_once() {
        assert_eq!(
            canonicalize_def_path("sniff_test", "config::normalized_path"),
            "sniff_test::config::normalized_path"
        );
        assert_eq!(
            canonicalize_def_path("std", "std::option::Option<T>::unwrap"),
            "std::option::Option<T>::unwrap"
        );
    }

    #[test]
    fn canonical_impl_paths_qualify_local_self_type() {
        assert_eq!(
            canonicalize_def_path(
                "sniff_test",
                "<cache::CachedArtifactAnalysis as std::clone::Clone>::clone"
            ),
            "<sniff_test::cache::CachedArtifactAnalysis as std::clone::Clone>::clone"
        );
        assert_eq!(
            canonicalize_def_path("std", "<std::vec::Vec<T> as std::clone::Clone>::clone"),
            "<std::vec::Vec<T> as std::clone::Clone>::clone"
        );
    }
}
