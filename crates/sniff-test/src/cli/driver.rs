//! Per-rustc-unit analysis orchestration.

mod effects;

use std::path::{Path, PathBuf};

use crate::cache::{
    CacheError, CacheExpectations, CachedArtifactAnalysis, CachedArtifactInfo,
    OUTCOME_FORMAT_VERSION, UnitOutcome, artifact_id,
};
use crate::config::SniffTestConfig;
use crate::dependency_cache::{DependencyAnalysisCache, DependencyInput};
use crate::report_roots::select_report_roots;
use anyhow::Context;
use rustc_hir::def_id::LOCAL_CRATE;
use rustc_middle::ty::TyCtxt;
use rustc_session::config::CrateType;

use super::args::{self, SniffTestArgs};
use super::diagnostics::emit_finding_diagnostic;
use super::findings::{Finding, collect_report_root_findings, resolve_findings};
use super::plugin::rustc_version;
use super::report::{AnalysisArtifactReport, CrateOutputScope, REPORT_FORMAT_VERSION};
use effects::{RootEffectAnalysis, analyze_effect_roots};

pub(crate) fn analyze_crate(
    tcx: TyCtxt<'_>,
    args: &SniffTestArgs,
    config: &SniffTestConfig,
    output_scope: CrateOutputScope,
) {
    let crate_name = tcx.crate_name(LOCAL_CRATE).to_string();

    let rustc_version = rustc_version();
    let externs = dependency_inputs(tcx);
    let dependency_cache = DependencyAnalysisCache::load(
        &args.cache_dir(),
        &externs,
        config,
        &CacheExpectations {
            tool_version: env!("CARGO_PKG_VERSION"),
            rustc_version: &rustc_version,
        },
    );
    for (extern_name, error) in dependency_cache.load_failures() {
        eprintln!(
            "sniff-test: warning: ignoring cached analysis for dependency `{extern_name}`: {error}"
        );
    }
    for ambiguous in dependency_cache.ambiguous_crate_names() {
        eprintln!(
            "sniff-test: warning: multiple compiled artifacts are named `{ambiguous}`; \
             cached effect evidence for that crate is disabled"
        );
    }

    let selection = select_report_roots(tcx, &config.analysis);
    let selection_has_roots = !selection.roots.is_empty();
    let emit_diagnostics = args.message_format == args::MessageFormat::Human
        && output_scope == CrateOutputScope::Workspace;
    let effect_analysis =
        analyze_effect_roots(tcx, selection, &config.analysis, config, &dependency_cache);
    let empty_report_roots = !selection_has_roots && effect_analysis.missing_roots.is_empty();
    let analysis_findings = collect_report_root_findings(
        tcx,
        &args.manifest_path(),
        empty_report_roots,
        &effect_analysis.missing_roots,
        &config.analysis.report_roots,
        &crate_name,
    );
    let analysis = AnalysisArtifact::new(
        tcx,
        output_scope,
        &dependency_cache,
        config,
        effect_analysis,
        analysis_findings,
    );
    if emit_diagnostics {
        for finding in &analysis.report.findings {
            emit_finding_diagnostic(tcx, finding.level, &finding.finding.diagnostic);
        }
    }
    if let Err(error) = analysis.cache.write(&args.cache_dir()) {
        if args.under_cargo {
            let diagnostic = tcx
                .dcx()
                .struct_err(format!("failed to write analysis cache: {error}"));
            let _ = diagnostic.emit();
        } else {
            eprintln!("sniff-test: warning: failed to write analysis cache: {error}");
        }
    }
    emit_report_and_outcome(
        tcx,
        args,
        &analysis.report,
        analysis.report.scope == CrateOutputScope::Workspace
            && analysis.report.has_denied_findings(),
    );
}

fn emit_report_and_outcome(
    tcx: TyCtxt<'_>,
    args: &SniffTestArgs,
    report: &AnalysisArtifactReport,
    has_denied_findings: bool,
) {
    let report_json = match serde_json::to_string(report) {
        Ok(report_json) => Some(report_json),
        Err(error) => {
            eprintln!("sniff-test: failed to encode JSON report: {error}");
            None
        }
    };
    if args.message_format == args::MessageFormat::Json
        && let Some(report_json) = &report_json
    {
        println!("{report_json}");
    }
    let outcome = UnitOutcome {
        format_version: OUTCOME_FORMAT_VERSION,
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        artifact_id: report.artifact.artifact_id.clone(),
        has_denied_findings,
        report_json,
    };
    if let Err(error) = write_unit_outcome_and_announce(args, &outcome) {
        report_unit_outcome_write_error(tcx, args, &error);
    }
}

fn report_unit_outcome_write_error(tcx: TyCtxt<'_>, args: &SniffTestArgs, error: &CacheError) {
    if args.under_cargo {
        let diagnostic = tcx
            .dcx()
            .struct_err(format!("failed to write unit outcome: {error}"));
        let _ = diagnostic.emit();
    } else {
        eprintln!("sniff-test: warning: failed to write unit outcome: {error}");
    }
}

fn write_unit_outcome_and_announce(
    args: &SniffTestArgs,
    outcome: &UnitOutcome,
) -> Result<(), CacheError> {
    let result = outcome.write(&args.cache_dir());
    // Deny findings fail this unit's compilation, so cargo never announces it
    // with a compiler-artifact message. This line puts the unit in the
    // frontend's build plan regardless; the frontend swallows it, users never
    // see it.
    if args.under_cargo {
        println!(
            r#"{{"reason":"sniff-test-outcome","artifact-id":{}}}"#,
            serde_json::json!(outcome.artifact_id)
        );
    }
    result
}

struct AnalysisArtifact {
    report: AnalysisArtifactReport,
    cache: CachedArtifactAnalysis,
}

impl AnalysisArtifact {
    #[allow(
        clippy::too_many_arguments,
        reason = "the constructor assembles independent analysis outputs without hiding them"
    )]
    fn new(
        tcx: TyCtxt<'_>,
        scope: CrateOutputScope,
        dependency_cache: &DependencyAnalysisCache,
        config: &SniffTestConfig,
        effect_analysis: RootEffectAnalysis,
        mut findings: Vec<Finding>,
    ) -> Self {
        let dependencies = dependency_cache.resolved_dependencies();
        let artifact = artifact_info(tcx);
        let tool_version = env!("CARGO_PKG_VERSION").to_owned();
        let rustc_version = rustc_version();
        findings.extend(effect_analysis.findings);
        let findings = resolve_findings(findings, config);
        let report = AnalysisArtifactReport {
            reason: String::from("sniff-test-artifact"),
            format_version: REPORT_FORMAT_VERSION,
            tool_version: tool_version.clone(),
            rustc_version: rustc_version.clone(),
            artifact: artifact.clone(),
            scope,
            dependencies: dependencies.clone(),
            findings,
        };
        let cache = CachedArtifactAnalysis::new(
            tool_version,
            rustc_version,
            artifact,
            dependencies,
            effect_analysis.function_summaries,
        );

        Self { report, cache }
    }
}

impl CrateOutputScope {
    pub(crate) fn current(args: &SniffTestArgs) -> anyhow::Result<Self> {
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
        // crates. Direct driver mode has no member list and falls back to
        // CARGO_PRIMARY_PACKAGE.
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

fn artifact_info(tcx: TyCtxt<'_>) -> CachedArtifactInfo {
    let crate_name = tcx.crate_name(LOCAL_CRATE).to_string();
    let extra_filename = tcx.sess.opts.cg.extra_filename.as_str();
    CachedArtifactInfo {
        artifact_id: artifact_id(
            &crate_name,
            (!extra_filename.is_empty()).then_some(extra_filename),
        ),
        crate_name,
    }
}

fn dependency_inputs(tcx: TyCtxt<'_>) -> Vec<DependencyInput> {
    let mut inputs = Vec::new();
    for (name, entry) in tcx.sess.opts.externs.iter() {
        // rustc accepts `--extern name` and resolves it through library search
        // paths, but without the resolved path we cannot identify one exact
        // artifact cache safely.
        let Some(files) = entry.files() else {
            continue;
        };
        inputs.extend(files.map(|file| DependencyInput {
            name: name.clone(),
            path: file.original().clone(),
        }));
    }
    inputs
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
