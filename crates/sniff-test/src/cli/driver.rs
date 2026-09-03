//! Per-rustc-unit analysis orchestration.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::artifact_cache::{
    ArtifactAnalysisCache, ArtifactInfo, ArtifactScope, CacheExpectations, RustcArtifactId,
};
use crate::compiler::extract::extract_artifact_facts;
use crate::compiler::source::verify_cached_marker_sources;
use crate::config::SniffTestConfig;
use crate::report_roots::select_report_roots;
use crate::workspace::{ArtifactAnalysisGraph, ExternArtifactInput};
use anyhow::Context;
use rustc_hir::def_id::{CrateNum, LOCAL_CRATE};
use rustc_middle::ty::TyCtxt;
use rustc_session::config::CrateType;
use rustc_span::symbol::Symbol;

use super::args::{CrateOutputScope, MessageFormat, SniffTestArgs};
use super::diagnostics::emit_finding_diagnostic;
use super::findings::{
    Finding, aggregate_human_findings, collect_report_root_findings, resolve_findings,
};
use super::interpretation::interpret_workspace;
use super::plugin::rustc_version;
use super::report::{AnalysisArtifactReport, REPORT_FORMAT_VERSION, ReportArtifact};

#[allow(
    clippy::too_many_lines,
    reason = "the rustc callback is intentionally linear extraction, tracing, and reporting orchestration"
)]
pub(crate) fn analyze_crate(
    tcx: TyCtxt<'_>,
    args: &SniffTestArgs,
    config: &SniffTestConfig,
    output_scope: CrateOutputScope,
) {
    let crate_name = tcx.crate_name(LOCAL_CRATE).to_string();
    let local_stable_crate_id = tcx.stable_crate_id(LOCAL_CRATE).as_u64();
    let rustc_version = rustc_version();
    let externs = match dependency_inputs(tcx) {
        Ok(externs) => externs,
        Err(error) => {
            emit_tool_error(tcx, error);
            return;
        }
    };
    let dependency_graph = ArtifactAnalysisGraph::load(
        &args.cache_dir(),
        &externs,
        &CacheExpectations {
            tool_version: env!("CARGO_PKG_VERSION"),
            rustc_version: &rustc_version,
        },
    );
    if !dependency_graph.is_complete() {
        let failures = dependency_graph
            .failures()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ");
        emit_tool_error(
            tcx,
            format!("failed to load required dependency artifact facts: {failures}"),
        );
        return;
    }
    if let Err(error) = verify_dependency_marker_sources(tcx, &dependency_graph) {
        emit_tool_error(tcx, error);
        return;
    }
    let facts = match extract_artifact_facts(tcx) {
        Ok(facts) => facts,
        Err(error) => {
            emit_tool_error(tcx, format!("failed to extract artifact facts: {error}"));
            return;
        }
    };
    let local_facts = if let Some(artifact) = local_cache_artifact_info(tcx, output_scope) {
        let cache = match ArtifactAnalysisCache::new(
            env!("CARGO_PKG_VERSION"),
            rustc_version.clone(),
            artifact,
            dependency_graph.direct_dependency_ids().collect(),
            facts,
        ) {
            Ok(cache) => cache,
            Err(error) => {
                emit_tool_error(tcx, format!("failed to create analysis cache: {error}"));
                return;
            }
        };
        if let Err(error) = cache.write(&args.cache_dir()) {
            emit_tool_error(tcx, format!("failed to write analysis cache: {error}"));
            return;
        }
        cache.facts
    } else if output_scope == CrateOutputScope::Dependency {
        emit_tool_error(
            tcx,
            "cannot persist required dependency artifact facts because rustc did not produce an SVH",
        );
        return;
    } else {
        facts
    };
    if output_scope == CrateOutputScope::Dependency {
        return;
    }

    let selection = select_report_roots(tcx, &config.analysis);
    let emit_diagnostics = args.under_cargo || args.message_format == MessageFormat::Human;
    let interpreted_findings = match interpret_workspace(
        tcx,
        &local_facts,
        local_stable_crate_id,
        &dependency_graph,
        &selection.roots,
        config,
    ) {
        Ok(findings) => findings,
        Err(error) => {
            emit_tool_error(tcx, format!("failed to trace effects: {error}"));
            return;
        }
    };
    let empty_report_roots = selection.roots.is_empty() && selection.missing_roots.is_empty();
    let mut findings = collect_report_root_findings(
        tcx,
        &args.manifest_path(),
        empty_report_roots,
        &selection.missing_roots,
        &config.analysis.report_roots,
        &crate_name,
    );
    findings.extend(interpreted_findings);
    let report = build_report(tcx, config, findings);
    if emit_diagnostics {
        for finding in aggregate_human_findings(&report.findings) {
            emit_finding_diagnostic(
                tcx,
                finding.level,
                &finding.finding.kind.lint_code(),
                &finding.finding.diagnostic,
            );
        }
    }
    emit_report(args, &report);
}

fn emit_tool_error(tcx: TyCtxt<'_>, message: impl Into<String>) {
    let diagnostic = tcx.dcx().struct_err(message.into());
    let _ = diagnostic.emit();
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

fn emit_report(args: &SniffTestArgs, report: &AnalysisArtifactReport) {
    if args.message_format != MessageFormat::Json {
        return;
    }
    match serde_json::to_string(report) {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("sniff-test: failed to encode JSON report: {error}");
        }
    }
}

fn build_report(
    tcx: TyCtxt<'_>,
    config: &SniffTestConfig,
    findings: Vec<Finding>,
) -> AnalysisArtifactReport {
    AnalysisArtifactReport {
        reason: String::from("sniff-test-artifact"),
        format_version: REPORT_FORMAT_VERSION,
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        rustc_version: rustc_version(),
        artifact: ReportArtifact {
            crate_name: tcx.crate_name(LOCAL_CRATE).to_string(),
        },
        findings: resolve_findings(findings, config),
    }
}

impl CrateOutputScope {
    #[must_use]
    const fn artifact_scope(self) -> ArtifactScope {
        match self {
            Self::Workspace => ArtifactScope::Workspace,
            Self::Dependency => ArtifactScope::Dependency,
        }
    }

    pub(crate) fn current(args: &SniffTestArgs) -> anyhow::Result<Self> {
        if !args.under_cargo {
            return Ok(args.direct_scope);
        }
        let cargo_manifest = std::env::var_os("CARGO_MANIFEST_PATH")
            .map(|path| {
                let path = PathBuf::from(path);
                path.canonicalize().with_context(|| {
                    format!("failed to canonicalize Cargo manifest {}", path.display())
                })
            })
            .transpose()?;
        Ok(Self::from_manifest_paths(
            &args.workspace_manifests,
            cargo_manifest.as_deref(),
            std::env::var_os("CARGO_PRIMARY_PACKAGE").is_some(),
        ))
    }

    #[must_use]
    fn from_manifest_paths(
        workspace_manifests: &[PathBuf],
        cargo_manifest: Option<&Path>,
        primary_package: bool,
    ) -> Self {
        // Membership comes from `cargo metadata`, plumbed by the frontend;
        // path prefixes would demote out-of-dir members and promote vendored
        // crates. CARGO_PRIMARY_PACKAGE is only the wrapper-mode fallback
        // when the frontend has no member list.
        let is_workspace_crate = match cargo_manifest {
            Some(manifest) if !workspace_manifests.is_empty() => {
                workspace_manifests.iter().any(|member| member == manifest)
            }
            _ => primary_package,
        };
        if is_workspace_crate {
            Self::Workspace
        } else {
            Self::Dependency
        }
    }
}

pub(crate) fn is_build_script(tcx: TyCtxt<'_>) -> bool {
    // Match rustc's own best-effort Cargo build-script detection in
    // `rustc_attr_parsing/attributes/diagnostic/check_cfg.rs`: Cargo invokes
    // these targets with `--crate-name build_script_build`.
    tcx.crate_name(LOCAL_CRATE).as_str() == "build_script_build"
}

pub(crate) fn is_proc_macro(tcx: TyCtxt<'_>) -> bool {
    // Proc macros execute while compiling their consumers; they do not ship as
    // runtime code whose effects belong in the consumer's invocation graph.
    tcx.crate_types().contains(&CrateType::ProcMacro)
}

fn local_cache_artifact_info(
    tcx: TyCtxt<'_>,
    output_scope: CrateOutputScope,
) -> Option<ArtifactInfo> {
    // Only outputs rustc can later load as crates need sidecars. In particular,
    // `cargo check` asks executable units to emit metadata, but their crate
    // type still is not loadable and rustc may omit the HIR hash required by
    // `crate_hash`. Interpret those units in memory without querying it.
    has_loadable_crate_output(tcx.crate_types()).then(|| ArtifactInfo {
        id: rustc_artifact_id(tcx, LOCAL_CRATE),
        crate_name: tcx.crate_name(LOCAL_CRATE).to_string(),
        scope: output_scope.artifact_scope(),
    })
}

fn has_loadable_crate_output(crate_types: &[CrateType]) -> bool {
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

fn describe_candidate_crates(names: &[String]) -> String {
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

pub(crate) fn load_config(
    args: &SniffTestArgs,
) -> Result<SniffTestConfig, crate::config::ConfigError> {
    let path = args.manifest_path();
    if path.exists() {
        SniffTestConfig::from_manifest_path(path)
    } else {
        Ok(SniffTestConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use rustc_session::config::CrateType;

    use crate::artifact_cache::ArtifactScope;

    use super::{CrateOutputScope, describe_candidate_crates, has_loadable_crate_output};

    #[test]
    fn ambiguous_loaded_crates_render_human_crate_names() {
        assert_eq!(
            describe_candidate_crates(&[String::from("alpha"), String::from("beta")]),
            "matched 2 loaded crates: `alpha`, `beta`"
        );
    }

    #[test]
    fn only_rust_linkable_crate_types_receive_persisted_cache_identities() {
        for crate_type in [
            CrateType::Executable,
            CrateType::StaticLib,
            CrateType::Cdylib,
            CrateType::Sdylib,
        ] {
            assert!(
                !has_loadable_crate_output(&[crate_type]),
                "{crate_type:?} must be interpreted in memory"
            );
        }
        for crate_type in [CrateType::Rlib, CrateType::Dylib, CrateType::ProcMacro] {
            assert!(
                has_loadable_crate_output(&[crate_type]),
                "{crate_type:?} needs a persisted identity"
            );
        }
        assert!(has_loadable_crate_output(&[
            CrateType::Executable,
            CrateType::Rlib,
        ]));
    }

    #[test]
    fn output_scope_classifies_workspace_dependency_and_fallback_crates() {
        let members = [
            PathBuf::from("/repo/crates/sniff-test/Cargo.toml"),
            PathBuf::from("/shared/utils/Cargo.toml"),
        ];

        assert_eq!(
            CrateOutputScope::from_manifest_paths(
                &members,
                Some(Path::new("/repo/crates/sniff-test/Cargo.toml")),
                false,
            ),
            CrateOutputScope::Workspace
        );
        assert_eq!(
            CrateOutputScope::from_manifest_paths(
                &members,
                Some(Path::new("/shared/utils/Cargo.toml")),
                false,
            ),
            CrateOutputScope::Workspace
        );
        assert_eq!(
            CrateOutputScope::from_manifest_paths(
                &members,
                Some(Path::new("/repo/vendor/foo/Cargo.toml")),
                false,
            ),
            CrateOutputScope::Dependency
        );
        assert_eq!(
            CrateOutputScope::from_manifest_paths(
                &members,
                Some(Path::new(
                    "/home/user/.cargo/registry/src/index.crates.io/hashbrown/Cargo.toml",
                )),
                true,
            ),
            CrateOutputScope::Dependency
        );
        assert_eq!(
            CrateOutputScope::from_manifest_paths(&[], None, true),
            CrateOutputScope::Workspace
        );
        assert_eq!(
            CrateOutputScope::from_manifest_paths(
                &[],
                Some(Path::new("/repo/crates/sniff-test/Cargo.toml")),
                false,
            ),
            CrateOutputScope::Dependency
        );
        assert_eq!(
            CrateOutputScope::Workspace.artifact_scope(),
            ArtifactScope::Workspace
        );
        assert_eq!(
            CrateOutputScope::Dependency.artifact_scope(),
            ArtifactScope::Dependency
        );
    }
}
