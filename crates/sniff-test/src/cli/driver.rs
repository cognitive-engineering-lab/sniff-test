//! Per-rustc-unit analysis orchestration.

use std::path::{Path, PathBuf};

use anyhow::Context;
use rustc_hir::def_id::LOCAL_CRATE;
use rustc_middle::ty::TyCtxt;
use rustc_session::config::CrateType;
use sniff_test_core::artifact_cache::ArtifactScope;
use sniff_test_core::config::SniffTestConfig;
use sniff_test_core::report_roots::select_report_roots;
use sniff_test_effects::selected_effect_objects;

use super::args::{CrateOutputScope, MessageFormat, SniffTestArgs};
use super::plugin::rustc_version;
use sniff_test_diagnostics::findings::collect_report_root_findings;
use sniff_test_diagnostics::interpretation::interpret_workspace;
use sniff_test_diagnostics::output::{
    build_report, emit_human_diagnostics, emit_json_report, emit_tool_error,
};

#[allow(
    clippy::too_many_lines,
    reason = "the rustc callback is intentionally linear extraction, tracing, and reporting orchestration"
)]
pub(crate) fn analyze_crate(
    tcx: TyCtxt<'_>,
    args: &SniffTestArgs,
    config: &SniffTestConfig,
    output_scope: CrateOutputScope,
    metadata_loader: &dyn rustc_metadata::creader::MetadataLoader,
) {
    let rustc_version = rustc_version();
    let effects = selected_effect_objects(&args.effects, config);
    let analysis = match sniff_test_core::analysis::analyze_artifact(
        tcx,
        &args.cache_dir(),
        output_scope.artifact_scope(),
        &rustc_version,
        &effects,
    ) {
        Ok(Some(analysis)) => analysis,
        Ok(None) => return,
        Err(error) => {
            emit_tool_error(tcx, error);
            return;
        }
    };
    let crate_name = analysis.crate_name.clone();
    let selection = select_report_roots(tcx, &config.analysis);
    let emit_diagnostics = args.under_cargo || args.message_format == MessageFormat::Human;
    let interpreted_findings = match interpret_workspace(
        tcx,
        &analysis.facts,
        analysis.local_stable_crate_id,
        &analysis.dependencies,
        metadata_loader,
        &selection.roots,
        config,
        &effects,
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
    let report = build_report(crate_name, rustc_version, config, &effects, findings);
    if emit_diagnostics {
        emit_human_diagnostics(tcx, &report);
    }
    if args.message_format == MessageFormat::Json {
        emit_json_report(&report);
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

pub(crate) fn load_config(
    args: &SniffTestArgs,
) -> Result<SniffTestConfig, Box<sniff_test_core::config::ConfigError>> {
    let path = args.manifest_path();
    if path.exists() {
        SniffTestConfig::from_manifest_path_with_effects(
            path,
            sniff_test_effects::registered_effect_configs(),
        )
        .map_err(Box::new)
    } else {
        Ok(SniffTestConfig {
            effects: sniff_test_effects::registered_effect_configs(),
            ..SniffTestConfig::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use rustc_session::config::CrateType;

    use sniff_test_core::artifact_cache::ArtifactScope;

    use super::CrateOutputScope;
    use sniff_test_core::analysis::{describe_candidate_crates, has_loadable_crate_output};

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
