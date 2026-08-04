//! Per-rustc-unit analysis orchestration.

mod interpretation;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::analysis::cache::{ArtifactAnalysisCache, ArtifactInfo, CacheExpectations, artifact_id};
use crate::analysis::extract::extract_artifact_ir;
use crate::analysis::graph::{ArtifactAnalysisGraph, ExternArtifactInput};
use crate::config::SniffTestConfig;
use crate::report_roots::select_report_roots;
use anyhow::Context;
use rustc_hir::def_id::{CrateNum, LOCAL_CRATE};
use rustc_middle::ty::TyCtxt;
use rustc_session::config::CrateType;
use rustc_span::symbol::Symbol;

use super::args::{self, SniffTestArgs};
use super::diagnostics::emit_finding_diagnostic;
use super::findings::{Finding, collect_report_root_findings, resolve_findings};
use super::plugin::rustc_version;
use super::report::{
    AnalysisArtifactReport, CrateOutputScope, REPORT_FORMAT_VERSION, ReportArtifact,
    ReportDependency,
};
use interpretation::interpret_workspace;

pub(crate) fn analyze_crate(
    tcx: TyCtxt<'_>,
    args: &SniffTestArgs,
    config: &SniffTestConfig,
    output_scope: CrateOutputScope,
) {
    let crate_name = tcx.crate_name(LOCAL_CRATE).to_string();
    let rustc_version = rustc_version();
    let compiler_fingerprint = compiler_fingerprint(tcx);
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
            format!("failed to load required dependency artifact IR: {failures}"),
        );
        return;
    }
    let ir = match extract_artifact_ir(tcx) {
        Ok(ir) => ir,
        Err(error) => {
            emit_tool_error(tcx, format!("failed to extract artifact IR: {error}"));
            return;
        }
    };
    let cache = match ArtifactAnalysisCache::new(
        env!("CARGO_PKG_VERSION"),
        rustc_version.clone(),
        compiler_fingerprint,
        artifact_info(tcx),
        dependency_graph.direct_dependency_refs().collect(),
        ir,
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
    if output_scope == CrateOutputScope::Dependency {
        return;
    }

    let selection = select_report_roots(tcx, &config.analysis);
    let emit_diagnostics = args.under_cargo || args.message_format == args::MessageFormat::Human;
    let interpretation = interpret_workspace(tcx, &cache, &dependency_graph, selection, config);
    let empty_report_roots =
        interpretation.selected_roots == 0 && interpretation.missing_roots.is_empty();
    let mut findings = collect_report_root_findings(
        tcx,
        &args.manifest_path(),
        empty_report_roots,
        &interpretation.missing_roots,
        &config.analysis.report_roots,
        &crate_name,
    );
    findings.extend(interpretation.findings);
    let report = build_report(tcx, &dependency_graph, config, findings);
    if emit_diagnostics {
        for finding in &report.findings {
            emit_finding_diagnostic(tcx, finding.level, &finding.finding.diagnostic);
        }
    }
    emit_report(args, &report);
}

fn emit_tool_error(tcx: TyCtxt<'_>, message: impl Into<String>) {
    let diagnostic = tcx.dcx().struct_err(message.into());
    let _ = diagnostic.emit();
}

fn emit_report(args: &SniffTestArgs, report: &AnalysisArtifactReport) {
    if args.message_format != args::MessageFormat::Json {
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
    dependency_graph: &ArtifactAnalysisGraph,
    config: &SniffTestConfig,
    findings: Vec<Finding>,
) -> AnalysisArtifactReport {
    let artifact = artifact_info(tcx);
    AnalysisArtifactReport {
        reason: String::from("sniff-test-artifact"),
        format_version: REPORT_FORMAT_VERSION,
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        rustc_version: rustc_version(),
        artifact: ReportArtifact {
            artifact_id: artifact.artifact_id,
            crate_name: artifact.crate_name,
        },
        dependencies: dependency_graph
            .direct_dependency_aliases()
            .map(|(extern_name, artifact_id)| ReportDependency {
                extern_name: extern_name.to_owned(),
                artifact_id: artifact_id.to_owned(),
            })
            .collect(),
        findings: resolve_findings(findings, config),
    }
}

impl CrateOutputScope {
    pub(crate) fn current(args: &SniffTestArgs) -> anyhow::Result<Self> {
        if !args.under_cargo {
            return Ok(match args.direct_scope {
                args::DirectInvocationScope::Workspace => Self::Workspace,
                args::DirectInvocationScope::Dependency => Self::Dependency,
            });
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

    pub(crate) fn for_crate(self, tcx: TyCtxt<'_>) -> Self {
        // Proc macros also execute during compilation rather than shipping as
        // target code. Use rustc's effective crate types so crate attributes
        // and command-line options are both handled by the compiler.
        if tcx.crate_types().contains(&CrateType::ProcMacro) {
            Self::Dependency
        } else {
            self
        }
    }
}

pub(crate) fn is_build_script(tcx: TyCtxt<'_>) -> bool {
    // Match rustc's own best-effort Cargo build-script detection in
    // `rustc_attr_parsing/attributes/diagnostic/check_cfg.rs`: Cargo invokes
    // these targets with `--crate-name build_script_build`.
    tcx.crate_name(LOCAL_CRATE).as_str() == "build_script_build"
}

fn artifact_info(tcx: TyCtxt<'_>) -> ArtifactInfo {
    let crate_name = tcx.crate_name(LOCAL_CRATE).to_string();
    let extra_filename = tcx.sess.opts.cg.extra_filename.as_str();
    ArtifactInfo {
        artifact_id: artifact_id(
            &crate_name,
            (!extra_filename.is_empty()).then_some(extra_filename),
        ),
        crate_name,
        stable_crate_id: tcx.stable_crate_id(LOCAL_CRATE).as_u64(),
        crate_hash: tcx.crate_hash(LOCAL_CRATE).to_hex(),
    }
}

fn dependency_inputs(tcx: TyCtxt<'_>) -> Result<Vec<ExternArtifactInput>, String> {
    let loaded = tcx
        .crates(())
        .iter()
        .copied()
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
            let loaded_paths = loaded
                .iter()
                .find_map(|(loaded_crate, paths)| {
                    (*loaded_crate == crate_num).then_some(paths)
                })
                .ok_or_else(|| {
                    format!(
                        "cannot load required dependency artifact IR for pathless extern `{name}` because its resolved rustc crate {crate_num:?} was not loaded"
                    )
                })?;
            let path = loaded_paths.first().cloned().ok_or_else(|| {
                format!(
                    "cannot load required dependency artifact IR for `{name}` because rustc recorded no artifact path for its loaded crate"
                )
            })?;
            inputs.push(extern_artifact_input(tcx, name.clone(), path, crate_num));
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
            // so it is intentionally absent from the composed IR graph.
            [] => continue,
            candidates => {
                return Err(format!(
                    "cannot bind required dependency artifact IR for `{name}` at [{supplied_paths}] to one loaded rustc crate; matched {candidates:?}"
                ));
            }
        };
        let Some(first_file) = files.first() else {
            return Err(format!(
                "cannot load required dependency artifact IR for `{name}` because rustc provided an empty artifact-path set"
            ));
        };
        let path = first_file.original().clone();
        inputs.push(extern_artifact_input(tcx, name.clone(), path, crate_num));
    }
    Ok(inputs)
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
    path: PathBuf,
    crate_num: CrateNum,
) -> ExternArtifactInput {
    let crate_name = tcx.crate_name(crate_num).to_string();
    let extra_filename = tcx.extra_filename(crate_num);
    ExternArtifactInput {
        name,
        path,
        artifact_id: artifact_id(
            &crate_name,
            (!extra_filename.is_empty()).then_some(extra_filename.as_str()),
        ),
        crate_name,
        stable_crate_id: tcx.stable_crate_id(crate_num).as_u64(),
        crate_hash: tcx.crate_hash(crate_num).to_hex(),
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

fn compiler_fingerprint(tcx: TyCtxt<'_>) -> String {
    let unstable = &tcx.sess.opts.unstable_opts;
    format!(
        "overflow-checks={};mir-opt-level={};always-encode-mir={};inline-mir={:?};inline-mir-threshold={:?};inline-mir-forwarder-threshold={:?};inline-mir-hint-threshold={:?};mir-enable-passes={:?}",
        tcx.sess.overflow_checks(),
        tcx.sess.mir_opt_level(),
        unstable.always_encode_mir,
        unstable.inline_mir,
        unstable.inline_mir_threshold,
        unstable.inline_mir_forwarder_threshold,
        unstable.inline_mir_hint_threshold,
        unstable.mir_enable_passes,
    )
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

    use super::CrateOutputScope;

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
    }
}
