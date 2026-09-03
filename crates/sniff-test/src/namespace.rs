//! Canonical Rust namespace rendering for config and cache matching.
//!
//! Configuration patterns are matched against stable [`NamespaceCandidates`]
//! forms of a definition: the crate root, such as `serde`, the definition-site
//! path, such as `serde::de::from_str`, and for impl items the self-type path,
//! such as `alloc::vec::Vec::index`. A human-oriented definition-backed form
//! is also a match candidate. The compiler session's visible re-export form is
//! retained only as a compatibility alias for existing policy patterns. Rust
//! crate names use underscores, not package-name hyphens, so users should
//! write `proc_macro2`, not `proc-macro2`.
//!
//! Cache identity uses [`StableDefPathHash`] instead of rendered paths:
//! pretty-printed paths differ between the defining crate's session and a
//! consumer's session (trait qualification, re-exports), while def path hashes
//! are read from crate metadata and agree by construction.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;

use rustc_data_structures::stable_hasher::ToStableHashKey;
use rustc_hir::def::DefKind;
use rustc_hir::def_id::DefId;
use rustc_middle::mono::MonoItem;
use rustc_middle::ty::print::{
    with_no_trimmed_paths, with_no_visible_paths, with_resolve_crate_name,
};
use rustc_middle::ty::{Instance, TyCtxt};
use rustc_span::{ExpnId, ExpnKind};
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

/// Returns the definition behind a real, definition-backed macro expansion.
///
/// rustc represents inert tool attributes such as `rustfmt::skip` with
/// [`ExpnKind::Macro`] even though they perform no macro expansion and have no
/// definition. Permanent macro topology and marker identity must omit those
/// marks consistently instead of inventing a definition for them.
pub(crate) fn definition_backed_macro(expansion: ExpnId) -> Option<DefId> {
    let data = expansion.expn_data();
    matches!(data.kind, ExpnKind::Macro(..))
        .then_some(data.macro_def_id)
        .flatten()
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct StableHash {
    first: u64,
    second: u64,
}

impl StableHash {
    const fn from_parts(first: u64, second: u64) -> Self {
        Self { first, second }
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
/// The primary forms are definition-backed and stable against
/// consumer-session re-exports. `display` retains rustc's human-oriented
/// impl/type rendering; `visible_alias` exists only for config compatibility.
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
    /// rustc's definition-backed, pretty-printed form.
    pub display: String,
    /// rustc's consumer-session visible path when it differs from `display`.
    ///
    /// This is never used for presentation or identity. It remains a policy
    /// match candidate so existing namespace configuration does not silently
    /// change meaning when display rendering becomes definition-backed.
    pub visible_alias: Option<String>,
}

impl NamespaceCandidates {
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        [
            Some(self.crate_name.as_str()),
            Some(self.def_site.as_str()),
            self.self_type.as_deref(),
            Some(self.display.as_str()),
            self.visible_alias.as_deref(),
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
                let display = canonical_namespace(tcx, def_id);
                let session_visible = canonicalize_def_path(&crate_name, &tcx.def_path_str(def_id));
                NamespaceCandidates {
                    self_type: impl_self_type_path(tcx, def_id, &crate_name),
                    visible_alias: (session_visible != display).then_some(session_visible),
                    display,
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
                let definition_path = with_resolve_crate_name!(with_no_trimmed_paths!(
                    with_no_visible_paths!(tcx.def_path_str(def_id))
                ));
                canonicalize_def_path(&crate_name, &definition_path)
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

        for malformed in [
            "0000000000000000000000000000000g",
            "000000000000000000000000000000000",
            "0000000000000000000000000000000",
        ] {
            let json = format!("\"{malformed}\"");
            assert!(serde_json::from_str::<StableDefPathHash>(&json).is_err());
        }
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
