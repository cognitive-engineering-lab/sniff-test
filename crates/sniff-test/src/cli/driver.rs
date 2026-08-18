//! Per-rustc-unit analysis orchestration.

mod interpretation;
mod typed_panic;
mod typed_panic_call;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::analysis::cache::{
    ArtifactAnalysisCache, ArtifactInfo, CacheExpectations, RustcArtifactId,
};
use crate::analysis::extract::{ExtractedArtifactBundle, extract_artifact_bundle};
use crate::analysis::facts::collection::CollectedArtifactSchemaPack;
use crate::analysis::facts::pack::{AnalysisRegistry, PackRegistrationError};
use crate::analysis::facts::registry::SchemaRegistry;
use crate::analysis::graph::{ArtifactAnalysisGraph, ExternArtifactInput};
use crate::analysis::source::{
    verify_cached_marker_sources_in, verify_cached_permanent_marker_sources_in,
};
use crate::config::SniffTestConfig;
use crate::report_roots::select_report_roots;
use anyhow::Context;
use rustc_hir::def_id::{CrateNum, LOCAL_CRATE};
use rustc_middle::ty::TyCtxt;
use rustc_session::config::CrateType;
use rustc_span::symbol::Symbol;

use super::args::{CrateOutputScope, MessageFormat, SniffTestArgs};
use super::diagnostics::emit_finding_diagnostic;
use super::findings::{Finding, collect_report_root_findings, resolve_findings};
use super::plugin::rustc_version;
use super::report::{AnalysisArtifactReport, REPORT_FORMAT_VERSION, ReportArtifact};
use interpretation::{InterpretWorkspaceRequest, interpret_workspace};

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
    let artifact_registry = match artifact_registry() {
        Ok(registry) => registry,
        Err(error) => {
            emit_tool_error(
                tcx,
                format!("failed to initialize artifact schemas: {error}"),
            );
            return;
        }
    };
    let dependency_graph = match load_dependency_graph(
        tcx,
        &args.cache_dir(),
        &externs,
        &rustc_version,
        artifact_registry.schemas(),
    ) {
        Ok(graph) => graph,
        Err(error) => return emit_tool_error(tcx, error),
    };
    let extracted = match extract_artifact_bundle(tcx) {
        Ok(extracted) => extracted,
        Err(error) => {
            emit_tool_error(tcx, format!("failed to extract artifact IR: {error}"));
            return;
        }
    };
    let (local, local_artifact_id) = if let Some(artifact) = local_cache_artifact_info(tcx) {
        match persist_local_analysis(
            extracted,
            artifact,
            &rustc_version,
            &dependency_graph,
            &args.cache_dir(),
            artifact_registry.schemas(),
        ) {
            Ok((local, artifact_id)) => (local, Some(artifact_id)),
            Err(error) => return emit_tool_error(tcx, error),
        }
    } else if output_scope == CrateOutputScope::Dependency {
        emit_tool_error(
            tcx,
            "cannot persist required dependency artifact IR because rustc did not produce an SVH",
        );
        return;
    } else {
        (extracted, None)
    };
    if output_scope == CrateOutputScope::Dependency {
        return;
    }

    let selection = select_report_roots(tcx, &config.analysis);
    let active_runtime_artifacts = active_runtime_artifacts(tcx);
    let emit_diagnostics = args.under_cargo || args.message_format == MessageFormat::Human;
    let interpreted_findings =
        match gate_workspace_interpretation(interpret_workspace(InterpretWorkspaceRequest {
            tcx,
            local: &local,
            local_artifact_id: local_artifact_id.as_ref(),
            local_stable_crate_id,
            dependencies: &dependency_graph,
            active_runtime_artifacts: &active_runtime_artifacts,
            report_roots: &selection.roots,
            config,
        })) {
            InterpretationGate::Proceed(findings) => findings,
            InterpretationGate::StopWithToolError(message) => {
                emit_tool_error(tcx, message);
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
        for finding in &report.findings {
            emit_finding_diagnostic(tcx, finding.level, &finding.finding.diagnostic);
        }
    }
    emit_report(args, &report);
}

#[derive(Debug, Eq, PartialEq)]
enum InterpretationGate<T> {
    Proceed(T),
    StopWithToolError(String),
}

fn gate_workspace_interpretation<T, E>(result: Result<T, E>) -> InterpretationGate<T>
where
    E: std::fmt::Display,
{
    match result {
        Ok(findings) => InterpretationGate::Proceed(findings),
        Err(error) => InterpretationGate::StopWithToolError(format!(
            "failed to interpret workspace analysis: {error}"
        )),
    }
}

fn persist_local_analysis(
    extracted: ExtractedArtifactBundle,
    artifact: ArtifactInfo,
    rustc_version: &str,
    dependencies: &ArtifactAnalysisGraph,
    cache_dir: &Path,
    schemas: &SchemaRegistry,
) -> Result<(ExtractedArtifactBundle, RustcArtifactId), String> {
    let artifact_id = artifact.id.clone();
    let cache = ArtifactAnalysisCache::new(
        env!("CARGO_PKG_VERSION"),
        rustc_version,
        artifact,
        dependencies.direct_dependency_ids().collect(),
        extracted.legacy_ir,
        extracted.facts,
        schemas,
    )
    .map_err(|error| format!("failed to create analysis cache: {error}"))?;
    cache
        .write(cache_dir, schemas)
        .map_err(|error| format!("failed to write analysis cache: {error}"))?;
    Ok((
        ExtractedArtifactBundle {
            legacy_ir: cache.legacy_ir,
            facts: cache.facts,
        },
        artifact_id,
    ))
}

fn artifact_registry() -> Result<AnalysisRegistry<()>, PackRegistrationError> {
    let mut registry = AnalysisRegistry::new();
    registry.install(&CollectedArtifactSchemaPack)?;
    Ok(registry)
}

fn load_dependency_graph(
    tcx: TyCtxt<'_>,
    cache_dir: &Path,
    externs: &[ExternArtifactInput],
    rustc_version: &str,
    schemas: &SchemaRegistry,
) -> Result<ArtifactAnalysisGraph, String> {
    let graph = ArtifactAnalysisGraph::load(
        cache_dir,
        externs,
        &CacheExpectations {
            tool_version: env!("CARGO_PKG_VERSION"),
            rustc_version,
        },
        schemas,
    );
    if !graph.is_complete() {
        let failures = graph
            .failures()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ");
        return Err(format!(
            "failed to load required dependency artifact IR: {failures}"
        ));
    }
    verify_dependency_marker_sources(tcx, &graph, schemas)?;
    Ok(graph)
}

fn emit_tool_error(tcx: TyCtxt<'_>, message: impl Into<String>) {
    let diagnostic = tcx.dcx().struct_err(message.into());
    let _ = diagnostic.emit();
}

fn verify_dependency_marker_sources(
    tcx: TyCtxt<'_>,
    dependencies: &ArtifactAnalysisGraph,
    schemas: &SchemaRegistry,
) -> Result<(), String> {
    for dependency in dependencies.artifacts() {
        verify_dependency_marker_source_in(tcx.sess.source_map(), dependency, schemas)?;
    }
    Ok(())
}

fn verify_dependency_marker_source_in(
    source_map: &rustc_span::source_map::SourceMap,
    dependency: &ArtifactAnalysisCache,
    schemas: &SchemaRegistry,
) -> Result<(), String> {
    let stale_error = |error| {
        format!(
            "cached source marker facts for artifact {} do not match the available source: {error}",
            dependency.artifact.id
        )
    };
    verify_cached_marker_sources_in(source_map, &dependency.legacy_ir).map_err(stale_error)?;
    verify_cached_permanent_marker_sources_in(source_map, &dependency.facts, schemas)
        .map_err(stale_error)
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

fn local_cache_artifact_info(tcx: TyCtxt<'_>) -> Option<ArtifactInfo> {
    // Only outputs rustc can later load as crates need sidecars. In particular,
    // `cargo check` asks executable units to emit metadata, but their crate
    // type still is not loadable and rustc may omit the HIR hash required by
    // `crate_hash`. Interpret those units in memory without querying it.
    has_loadable_crate_output(tcx.crate_types()).then(|| ArtifactInfo {
        id: rustc_artifact_id(tcx, LOCAL_CRATE),
        crate_name: tcx.crate_name(LOCAL_CRATE).to_string(),
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

fn active_runtime_artifacts(tcx: TyCtxt<'_>) -> Vec<RustcArtifactId> {
    let mut artifacts = tcx
        .crates(())
        .iter()
        .copied()
        .map(|crate_num| rustc_artifact_id(tcx, crate_num))
        .collect::<Vec<_>>();
    artifacts.sort();
    artifacts.dedup();
    artifacts
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
            // so it is intentionally absent from the composed IR graph.
            [] => continue,
            candidates => {
                let candidate_names = candidates
                    .iter()
                    .map(|crate_num| tcx.crate_name(*crate_num).to_string())
                    .collect::<Vec<_>>();
                let candidates = describe_candidate_crates(&candidate_names);
                return Err(format!(
                    "cannot bind required dependency artifact IR for `{name}` at [{supplied_paths}] to one loaded rustc crate; {candidates}"
                ));
            }
        };
        inputs.push(extern_artifact_input(tcx, name.clone(), crate_num));
    }
    Ok(inputs)
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
    use std::fs;
    use std::path::{Path, PathBuf};

    use rustc_session::config::CrateType;
    use rustc_span::Pos;
    use rustc_span::source_map::{FilePathMapping, SourceMap};

    use crate::analysis::facts::builder::ArtifactDbBuilder;
    use crate::analysis::facts::evaluation::DomainId;
    use crate::analysis::facts::human::EvidenceClaimSelector;
    use crate::analysis::facts::human::markers::{
        MarkerClaimEntity, MarkerClaimKey, MarkerOccurrenceEntity, MarkerOccurrenceHasClaim,
        MarkerOccurrenceHasSourceAnchor, MarkerOccurrenceKey,
    };
    use crate::analysis::facts::panic::model::MirAssertFact;
    use crate::analysis::facts::program::topology::CallOccurrenceEntity;
    use crate::analysis::facts::program::{
        SourceAnchorEntity, SourceAnchorInFile, SourceAnchorKey, SourceFileEntity,
    };
    use crate::analysis::facts::safety::operations::UnsafeOperationEntity;
    use crate::analysis::facts::schema::RowSchema;
    use crate::analysis::ir::ArtifactAnalysisIr;
    use crate::analysis::source::stable_source_file_id;

    use super::{
        ArtifactAnalysisCache, ArtifactInfo, CrateOutputScope, InterpretationGate, RustcArtifactId,
        artifact_registry, describe_candidate_crates, gate_workspace_interpretation,
        has_loadable_crate_output, verify_dependency_marker_source_in,
    };

    #[test]
    fn production_registry_validates_permanent_artifact_rows() {
        let registry = artifact_registry().unwrap();

        for schema in [
            CallOccurrenceEntity::ID,
            MarkerOccurrenceEntity::ID,
            UnsafeOperationEntity::ID,
            MirAssertFact::ID,
        ] {
            assert!(
                registry
                    .schemas()
                    .descriptors()
                    .any(|descriptor| descriptor.id().as_str() == schema),
                "production registry omitted {schema}"
            );
        }
    }

    #[test]
    fn dependency_gate_rejects_stale_permanent_panic_marker_with_empty_legacy_ir() {
        rustc_span::create_default_session_globals_then(|| {
            let directory = tempfile::tempdir().expect("temp directory");
            let path = directory.path().join("dependency.rs");
            fs::write(&path, "// PANIC: expected panic\nfn old() {}\n")
                .expect("write dependency source");
            let extraction_map = SourceMap::new(FilePathMapping::empty());
            let extracted = extraction_map
                .load_file(&path)
                .expect("load dependency source");
            let source_id = stable_source_file_id(&extracted);
            let byte_len = u64::from(extracted.normalized_source_len.to_u32());
            let registry = artifact_registry().unwrap();
            let mut builder = ArtifactDbBuilder::new();
            for descriptor in registry.schemas().descriptors() {
                builder.declare_table(descriptor).unwrap();
            }

            let file = builder
                .insert_entity(&SourceFileEntity::new(
                    source_id.as_str(),
                    path.to_string_lossy(),
                    extracted.src_hash.to_string(),
                    byte_len,
                ))
                .unwrap();
            let anchor_key = SourceAnchorKey::new(source_id.as_str(), 0, byte_len);
            let anchor = builder
                .insert_entity(&SourceAnchorEntity::new(anchor_key.clone()))
                .unwrap();
            builder
                .relate(&anchor, &file, &SourceAnchorInFile::new())
                .unwrap();
            let occurrence_key = MarkerOccurrenceKey::new(anchor_key, None);
            let occurrence = builder
                .insert_entity(&MarkerOccurrenceEntity::new(
                    occurrence_key.clone(),
                    Vec::new(),
                ))
                .unwrap();
            builder
                .relate(
                    &occurrence,
                    &anchor,
                    &MarkerOccurrenceHasSourceAnchor::new(),
                )
                .unwrap();
            let claim = builder
                .insert_entity(&MarkerClaimEntity::new(
                    MarkerClaimKey::new(
                        occurrence_key,
                        DomainId::new("sniff-test.panic").unwrap(),
                        0,
                    ),
                    EvidenceClaimSelector::Unnamed,
                    "expected panic",
                ))
                .unwrap();
            builder
                .relate(&occurrence, &claim, &MarkerOccurrenceHasClaim::new())
                .unwrap();
            let facts = builder.finalize(registry.schemas()).unwrap();
            let cache = ArtifactAnalysisCache::new(
                env!("CARGO_PKG_VERSION"),
                "rustc-test",
                ArtifactInfo {
                    id: RustcArtifactId::new(1, "0123456789abcdef0123456789abcdef"),
                    crate_name: String::from("dependency"),
                },
                Vec::new(),
                ArtifactAnalysisIr::new(Vec::new(), Vec::new()).unwrap(),
                facts,
                registry.schemas(),
            )
            .unwrap();
            assert!(cache.legacy_ir.functions.is_empty());
            fs::write(&path, "// marker removed\nfn new() {}\n")
                .expect("replace dependency source");
            let active = SourceMap::new(FilePathMapping::empty());

            let error = verify_dependency_marker_source_in(&active, &cache, registry.schemas())
                .expect_err("production dependency verification must reject stale typed markers");

            assert!(error.contains("cached source marker facts for artifact"));
            assert!(error.contains("content hash"));
        });
    }

    #[test]
    fn successful_workspace_interpretation_forwards_findings_to_reporting() {
        let findings = vec!["first", "second"];

        let gate = gate_workspace_interpretation::<_, &str>(Ok(findings.clone()));

        assert_eq!(gate, InterpretationGate::Proceed(findings));
    }

    #[test]
    fn failed_workspace_interpretation_plans_one_tool_error_and_no_report() {
        let gate = gate_workspace_interpretation::<Vec<&str>, _>(Err("invalid typed issue"));

        let (tool_error_actions, report_actions) = match gate {
            InterpretationGate::Proceed(_) => (0, 1),
            InterpretationGate::StopWithToolError(message) => {
                assert_eq!(
                    message,
                    "failed to interpret workspace analysis: invalid typed issue"
                );
                (1, 0)
            }
        };
        assert_eq!(tool_error_actions, 1);
        assert_eq!(report_actions, 0);
    }

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
    }
}
