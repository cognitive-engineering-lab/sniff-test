//! Canonical Rust namespace rendering for config and cache matching.
//!
//! Configuration patterns are matched against two related namespace forms:
//! the crate root, such as `serde`, and fully-qualified item paths, such as
//! `serde::de::from_str`. Rust crate names use underscores, not package-name
//! hyphens, so users should write `proc_macro2`, not `proc-macro2`.

use rustc_hir::def_id::DefId;
use rustc_middle::ty::TyCtxt;

#[must_use]
pub fn canonical_namespace(tcx: TyCtxt<'_>, def_id: DefId) -> String {
    let crate_name = tcx.crate_name(def_id.krate).to_string();
    canonicalize_def_path(&crate_name, &tcx.def_path_str(def_id))
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
