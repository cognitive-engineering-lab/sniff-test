//! Exact rustc crate dependencies, including implicit and toolchain dependencies.

use std::collections::{BTreeMap, BTreeSet};

use rustc_hir::def_id::LOCAL_CRATE;
use rustc_metadata::creader::MetadataLoader;
use rustc_middle::ty::TyCtxt;

use crate::artifact::ArtifactFacts;
use crate::workspace::ArtifactAnalysisGraph;

pub fn load_crate_dependencies(
    tcx: TyCtxt<'_>,
    local: &ArtifactFacts,
    cached: &ArtifactAnalysisGraph,
    metadata_loader: &dyn MetadataLoader,
) -> Result<BTreeMap<u64, BTreeSet<u64>>, String> {
    let owners = local
        .functions
        .iter()
        .chain(
            cached
                .artifacts()
                .flat_map(|artifact| &artifact.facts.functions),
        )
        .map(|body| body.function.def_path_hash.stable_crate_id())
        .collect::<BTreeSet<_>>();
    let identities = tcx
        .crates(())
        .iter()
        .map(|&crate_num| {
            (
                tcx.crate_hash(crate_num).to_string(),
                tcx.stable_crate_id(crate_num).as_u64(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut dependencies = BTreeMap::from([(
        tcx.stable_crate_id(LOCAL_CRATE).as_u64(),
        identities.values().copied().collect(),
    )]);
    for &crate_num in tcx.crates(()) {
        let owner = tcx.stable_crate_id(crate_num).as_u64();
        if owner == tcx.stable_crate_id(LOCAL_CRATE).as_u64() || !owners.contains(&owner) {
            continue;
        }
        let paths = tcx.crate_extern_paths(crate_num);
        let path = paths
            .iter()
            .map(|path| path.with_extension("rmeta"))
            .find(|path| path.is_file())
            .or_else(|| paths.iter().find(|path| path.is_file()).cloned())
            .ok_or_else(|| {
                format!(
                    "cannot inspect dependencies of `{}`: no metadata file is available",
                    tcx.crate_name(crate_num)
                )
            })?;
        let mut listing = Vec::new();
        rustc_metadata::locator::list_file_metadata(
            &tcx.sess.target,
            &path,
            metadata_loader,
            &mut listing,
            &[String::from("root")],
            tcx.sess.cfg_version,
        )
        .map_err(|error| {
            format!(
                "cannot inspect dependencies of `{}`: {error}",
                tcx.crate_name(crate_num)
            )
        })?;
        let listing = String::from_utf8(listing).map_err(|error| error.to_string())?;
        dependencies.insert(
            owner,
            parse_dependencies(
                &listing,
                &tcx.crate_hash(crate_num).to_string(),
                &identities,
            )?,
        );
    }
    Ok(dependencies)
}

/// The compiler's root listing is version-bound to the rustc hosting us.
/// Bind dependencies by their exact SVH, never by package or crate names.
fn parse_dependencies(
    listing: &str,
    expected_hash: &str,
    identities: &BTreeMap<String, u64>,
) -> Result<BTreeSet<u64>, String> {
    let hash_matches = listing.lines().any(|line| {
        line.strip_prefix("hash ")
            .and_then(|rest| rest.split_whitespace().next())
            == Some(expected_hash)
    });
    if !hash_matches {
        return Err(String::from(
            "dependency metadata does not identify the loaded rustc artifact",
        ));
    }
    let (_, dependencies) = listing
        .split_once("=External Dependencies=\n")
        .ok_or_else(|| String::from("rustc metadata listing has no dependency section"))?;
    dependencies
        .lines()
        .take_while(|line| !line.trim().is_empty())
        .map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 4 || fields[2] != "hash" {
                return Err(format!("invalid rustc dependency metadata: {line}"));
            }
            identities.get(fields[3]).copied().ok_or_else(|| {
                format!(
                    "dependency artifact {} ({}) is not loaded",
                    fields[1], fields[3]
                )
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::parse_dependencies;
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn dependencies_use_exact_artifact_hashes() {
        let identities = BTreeMap::from([(String::from("aaaa"), 1), (String::from("bbbb"), 2)]);
        let listing = "hash cccc stable_crate_id StableCrateId(3)\n=External Dependencies=\n1 dep-first hash aaaa host_hash None\n2 dep-second hash bbbb host_hash None\n\n";
        assert_eq!(
            parse_dependencies(listing, "cccc", &identities).unwrap(),
            BTreeSet::from([1, 2])
        );
        assert!(parse_dependencies(listing, "dddd", &identities).is_err());
        assert!(parse_dependencies(listing, "cccc", &BTreeMap::new()).is_err());
    }
}
