//! Canonical Rust namespace rendering for config and cache matching.
//!
//! Configuration patterns are matched against the session-independent
//! [`NamespaceCandidates`] forms of a definition: the crate root, such as
//! `serde`, the definition-site path, such as `serde::de::from_str`, and for
//! impl items the self-type path, such as `alloc::vec::Vec::index`. Rust crate
//! names use underscores, not package-name hyphens, so users should write
//! `proc_macro2`, not `proc-macro2`.
//!
//! Cache identity uses [`stable_def_path_hash`] instead of rendered paths:
//! pretty-printed paths differ between the defining crate's session and a
//! consumer's session (trait qualification, re-exports), while def path hashes
//! are read from crate metadata and agree by construction.

use std::cell::RefCell;
use std::collections::HashMap;

use rustc_hir::def::DefKind;
use rustc_hir::def_id::DefId;
use rustc_middle::ty::TyCtxt;

// The driver runs one rustc session per process and the analysis is
// single-threaded, so `DefId`-keyed caches stay valid for the process
// lifetime. Rendering def paths is a hot cost: policy checks run per edge of
// every per-root traversal, and `def_path_str` re-pretty-prints each time.
thread_local! {
    static NAMESPACE_CACHE: RefCell<HashMap<DefId, String>> = RefCell::new(HashMap::new());
    static CANDIDATES_CACHE: RefCell<HashMap<DefId, NamespaceCandidates>> =
        RefCell::new(HashMap::new());
}

/// Session-independent identity for a definition, as a 32-hex-digit string of
/// the stable crate id followed by the local def path hash.
#[must_use]
pub fn stable_def_path_hash(tcx: TyCtxt<'_>, def_id: DefId) -> String {
    let hash = tcx.def_path_hash(def_id);
    format!(
        "{:016x}{:016x}",
        hash.stable_crate_id().as_u64(),
        hash.local_hash().as_u64()
    )
}

/// Session-independent namespace forms a definition can be matched against.
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
    /// The legacy pretty-printed form kept for pattern back-compat.
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
    use super::canonicalize_def_path;

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
