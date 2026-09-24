//! Per-rustc-unit fact extraction, dependency binding, and cache preparation.

use std::collections::BTreeSet;
use std::path::Path;

use rustc_hir::def_id::{CrateNum, LOCAL_CRATE};
use rustc_middle::ty::TyCtxt;
use rustc_session::config::CrateType;
use rustc_span::symbol::Symbol;

use crate::artifact::ArtifactFacts;
use crate::artifact_cache::{
    ArtifactAnalysisCache, ArtifactInfo, ArtifactScope, CacheExpectations, RustcArtifactId,
};
use crate::compiler::extract::extract_artifact_facts;
use crate::compiler::source::verify_cached_marker_sources;
use crate::effects::Effect;
use crate::workspace::{ArtifactAnalysisGraph, ExternArtifactInput};

pub struct AnalyzedArtifact {
    pub crate_name: String,
    pub local_stable_crate_id: u64,
    pub rustc_version: String,
    pub facts: ArtifactFacts,
    pub dependencies: ArtifactAnalysisGraph,
}

/// Extract and cache one rustc unit. Dependency units produce facts but no report.
pub fn analyze_artifact(
    tcx: TyCtxt<'_>,
    cache_dir: &Path,
    output_scope: ArtifactScope,
    rustc_version: &str,
    effects: &[Box<dyn Effect + '_>],
) -> Result<Option<AnalyzedArtifact>, String> {
    let externs = dependency_inputs(tcx)?;
    let dependencies = ArtifactAnalysisGraph::load(
        cache_dir,
        &externs,
        &CacheExpectations {
            tool_version: env!("CARGO_PKG_VERSION"),
            rustc_version,
        },
    );
    if !dependencies.is_complete() {
        let failures = dependencies
            .failures()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ");
        return Err(format!(
            "failed to load required dependency artifact facts: {failures}"
        ));
    }
    verify_dependency_marker_sources(tcx, &dependencies)?;
    let facts = extract_artifact_facts(tcx, effects)
        .map_err(|error| format!("failed to extract artifact facts: {error}"))?;
    let facts = if let Some(artifact) = local_cache_artifact_info(tcx, output_scope) {
        let cache = ArtifactAnalysisCache::new(
            env!("CARGO_PKG_VERSION"),
            rustc_version.to_owned(),
            artifact,
            dependencies.direct_dependency_ids().collect(),
            facts,
        )
        .map_err(|error| format!("failed to create analysis cache: {error}"))?;
        cache
            .write(cache_dir)
            .map_err(|error| format!("failed to write analysis cache: {error}"))?;
        cache.facts
    } else if output_scope == ArtifactScope::Dependency {
        return Err(String::from(
            "cannot persist required dependency artifact facts because rustc did not produce an SVH",
        ));
    } else {
        facts
    };
    if output_scope == ArtifactScope::Dependency {
        return Ok(None);
    }
    Ok(Some(AnalyzedArtifact {
        crate_name: tcx.crate_name(LOCAL_CRATE).to_string(),
        local_stable_crate_id: tcx.stable_crate_id(LOCAL_CRATE).as_u64(),
        rustc_version: rustc_version.to_owned(),
        facts,
        dependencies,
    }))
}

fn verify_dependency_marker_sources(
    tcx: TyCtxt<'_>,
    dependencies: &ArtifactAnalysisGraph,
) -> Result<(), String> {
    for dependency in dependencies.artifacts() {
        verify_cached_marker_sources(tcx, &dependency.facts).map_err(|error| {
            format!(
                "cached source marker facts for artifact {} do not match the available source: {error}",
                dependency.artifact.id
            )
        })?;
    }
    Ok(())
}

fn local_cache_artifact_info(tcx: TyCtxt<'_>, output_scope: ArtifactScope) -> Option<ArtifactInfo> {
    // Only outputs rustc can later load as crates need sidecars. In particular,
    // `cargo check` asks executable units to emit metadata, but their crate
    // type still is not loadable and rustc may omit the HIR hash required by
    // `crate_hash`. Interpret those units in memory without querying it.
    has_loadable_crate_output(tcx.crate_types()).then(|| ArtifactInfo {
        id: rustc_artifact_id(tcx, LOCAL_CRATE),
        crate_name: tcx.crate_name(LOCAL_CRATE).to_string(),
        scope: output_scope,
    })
}

pub fn has_loadable_crate_output(crate_types: &[CrateType]) -> bool {
    crate_types.iter().copied().any(CrateType::has_metadata)
}

fn rustc_artifact_id(tcx: TyCtxt<'_>, crate_num: CrateNum) -> RustcArtifactId {
    RustcArtifactId::new(
        tcx.stable_crate_id(crate_num).as_u64(),
        tcx.crate_hash(crate_num).to_hex(),
    )
}

fn dependency_inputs(tcx: TyCtxt<'_>) -> Result<Vec<ExternArtifactInput>, String> {
    let loaded = tcx
        .crates(())
        .iter()
        .copied()
        .filter(|crate_num| !is_compile_time_only_dependency(tcx, *crate_num))
        .map(|crate_num| (crate_num, tcx.crate_extern_paths(crate_num).clone()))
        .collect::<Vec<_>>();
    let mut inputs = Vec::new();
    for (name, entry) in tcx.sess.opts.externs.iter() {
        // rustc accepts `--extern name` and resolves it through library search
        // paths. In that form the session entry has no supplied files, so bind
        // it through rustc's direct loaded-crate identity instead.
        let Some(files) = entry.files() else {
            // The extern-prelude alias is distinct from the crate's metadata
            // name, so use rustc's exact resolved-name table.
            let Some(crate_num) = resolved_extern_crate(tcx, name) else {
                // rustc assigns no CrateNum to an unused --extern.
                continue;
            };
            if is_compile_time_only_dependency(tcx, crate_num) {
                continue;
            }
            inputs.push(extern_artifact_input(tcx, name.clone(), crate_num));
            continue;
        };
        let files = files.collect::<Vec<_>>();
        let matching = loaded
            .iter()
            .filter_map(|(crate_num, loaded_paths)| {
                files
                    .iter()
                    .any(|file| {
                        loaded_paths.iter().any(|loaded_path| {
                            loaded_path == file.canonicalized()
                                || same_artifact_path(file.original(), loaded_path)
                        })
                    })
                    .then_some(*crate_num)
            })
            .collect::<BTreeSet<_>>();
        let supplied_paths = files
            .iter()
            .map(|file| file.original().display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let crate_num = match matching.iter().copied().collect::<Vec<_>>().as_slice() {
            [crate_num] => *crate_num,
            // rustc does not assign a CrateNum to a truly unused --extern.
            // Such an artifact cannot be reached from any body in this unit,
            // so it is intentionally absent from the composed artifact graph.
            [] => continue,
            candidates => {
                let candidate_names = candidates
                    .iter()
                    .map(|crate_num| tcx.crate_name(*crate_num).to_string())
                    .collect::<Vec<_>>();
                let candidates = describe_candidate_crates(&candidate_names);
                return Err(format!(
                    "cannot bind required dependency artifact facts for `{name}` at [{supplied_paths}] to one loaded rustc crate; {candidates}"
                ));
            }
        };
        inputs.push(extern_artifact_input(tcx, name.clone(), crate_num));
    }
    Ok(inputs)
}

fn is_compile_time_only_dependency(tcx: TyCtxt<'_>, crate_num: CrateNum) -> bool {
    // rustc uses this same classification when deciding which dependencies
    // are omitted from the linked runtime artifact. Unlike exported macro
    // DefIds, it also identifies a valid proc-macro crate that exports none.
    tcx.crate_dep_kind(crate_num).macros_only()
}

#[must_use]
pub fn describe_candidate_crates(names: &[String]) -> String {
    let count = names.len();
    let names = names
        .iter()
        .map(|name| format!("`{name}`"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("matched {count} loaded crates: {names}")
}

fn resolved_extern_crate(tcx: TyCtxt<'_>, name: &str) -> Option<CrateNum> {
    let cstore = tcx.cstore_untracked();
    cstore
        .as_any()
        .downcast_ref::<rustc_metadata::creader::CStore>()?
        .resolved_extern_crate(Symbol::intern(name))
}

fn extern_artifact_input(
    tcx: TyCtxt<'_>,
    name: String,
    crate_num: CrateNum,
) -> ExternArtifactInput {
    ExternArtifactInput {
        name,
        artifact_id: rustc_artifact_id(tcx, crate_num),
    }
}

fn same_artifact_path(left: &Path, right: &Path) -> bool {
    left == right
        || left
            .canonicalize()
            .ok()
            .zip(right.canonicalize().ok())
            .is_some_and(|(left, right)| left == right)
}
