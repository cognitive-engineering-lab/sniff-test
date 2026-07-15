//! Selection of current-crate functions that should produce reports.
//!
//! Report roots are not the whole reachability graph. They are the starting
//! functions sniff-test analyzes when deciding which panic paths to report.
//! Generic roots are analyzed structurally with identity generic arguments.

use std::collections::HashSet;
use std::ops::Range;

use rustc_hir::def::DefKind;
use rustc_hir::def_id::{LOCAL_CRATE, LocalDefId};
use rustc_middle::ty::{Instance, TyCtxt};

use crate::config::{AnalysisConfig, AnalysisLintConfig, LintLevel, PanicConfig, ReportRootSet};
use crate::namespace::canonical_namespace;
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct ReportRootSelection<'tcx> {
    /// Concrete or generic functions selected for analysis/reporting.
    pub roots: Vec<ReportRoot<'tcx>>,
    /// Explicitly configured function paths that were not found in this crate.
    pub missing_roots: Vec<MissingReportRoot>,
}

#[derive(Debug, Clone)]
pub struct MissingReportRoot {
    /// Fully qualified function path from `[analysis].report-roots`.
    pub path: String,
    /// Byte range of the TOML string value in the sniff-test manifest.
    pub source_span: Range<usize>,
    pub reason: MissingRootReason,
}

/// Why a configured report root produced no analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingRootReason {
    /// No function with that path exists in the current crate.
    NotFound,
    /// The function exists but matches `[panics].ignored-namespaces`.
    Ignored,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReportRootFindingKind {
    EmptyReportRoots,
    MissingReportRoot,
    IgnoredReportRoot,
}

impl ReportRootFindingKind {
    #[must_use]
    pub fn lint_level(self, lints: AnalysisLintConfig) -> LintLevel {
        match self {
            Self::EmptyReportRoots => lints.empty_report_roots,
            Self::MissingReportRoot => lints.missing_report_root,
            Self::IgnoredReportRoot => lints.ignored_report_root,
        }
    }
}

impl MissingRootReason {
    #[must_use]
    pub fn finding_kind(self) -> ReportRootFindingKind {
        match self {
            Self::NotFound => ReportRootFindingKind::MissingReportRoot,
            Self::Ignored => ReportRootFindingKind::IgnoredReportRoot,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ReportRoot<'tcx> {
    /// Monomorphic function that can be analyzed immediately.
    Concrete {
        // WC: the LocalDefId should be retrievable from the Instance, why do we store it separately?
        local: LocalDefId,        
        instance: Instance<'tcx>,
    },
    /// Generic function that requires monomorphization before reachability analysis.
    Generic { local: LocalDefId },
}

impl ReportRoot<'_> {
    #[must_use]
    pub fn local_def_id(self) -> LocalDefId {
        match self {
            Self::Concrete { local, .. } | Self::Generic { local } => local,
        }
    }
}

#[must_use]
pub fn select_report_roots<'tcx>(
    tcx: TyCtxt<'tcx>,
    analysis_config: &AnalysisConfig,
    panic_config: &PanicConfig,
) -> ReportRootSelection<'tcx> {
    let crate_name = tcx.crate_name(LOCAL_CRATE).to_string();
    if panic_config.ignores_namespace(&crate_name) {
        return ReportRootSelection {
            roots: Vec::new(),
            missing_roots: Vec::new(),
        };
    }

    let mut roots = HashSet::new();

    // WC: style nit, I would rewrite this as:
    //      let missing_roots = match .. { .. };
    //      sorted_selection(tcx, panic_config, roots, missing_roots)
    // Rather than have two separate sorted_selection calls.
    match &analysis_config.report_roots {
        ReportRootSet::Public => {
            roots.extend(public_local_fn_defs(tcx));
        }
        ReportRootSet::All => {
            roots.extend(analyzable_local_fn_defs(tcx));
        }
        ReportRootSet::Explicit(configured_roots) => {
            let mut missing_roots = Vec::new();
            for configured_root in configured_roots {
                match find_local_fn_by_path(tcx, configured_root.path()) {
                    // An explicitly configured root silently swallowed by the
                    // ignore list would look analyzed while nothing ran.
                    Some(local) if panic_config.ignores_def(tcx, local.to_def_id()) => {
                        missing_roots.push(MissingReportRoot {
                            path: configured_root.path().to_owned(),
                            source_span: configured_root.source_span(),
                            reason: MissingRootReason::Ignored,
                        });
                    }
                    Some(local) => {
                        roots.insert(local);
                    }
                    None => {
                        missing_roots.push(MissingReportRoot {
                            path: configured_root.path().to_owned(),
                            source_span: configured_root.source_span(),
                            reason: MissingRootReason::NotFound,
                        });
                    }
                }
            }

            return sorted_selection(tcx, panic_config, roots, missing_roots);
        }
    }

    sorted_selection(tcx, panic_config, roots, Vec::new())
}

fn sorted_selection<'tcx>(
    tcx: TyCtxt<'tcx>,
    config: &PanicConfig,
    roots: HashSet<LocalDefId>,
    missing_roots: Vec<MissingReportRoot>,
) -> ReportRootSelection<'tcx> {
    let mut roots = roots
        .into_iter()
        // WC: this is mixing concerns. I would 
        .filter(|local| !config.ignores_def(tcx, local.to_def_id()))
        .map(|local| report_root(tcx, local))
        .collect::<Vec<_>>();
        
    // WC: you prob want sort_by_cached_key
    roots.sort_by(|left, right| {
        canonical_namespace(tcx, left.local_def_id().to_def_id())
            .cmp(&canonical_namespace(tcx, right.local_def_id().to_def_id()))
    });

    ReportRootSelection {
        roots,
        missing_roots,
    }
}

fn report_root(tcx: TyCtxt<'_>, local: LocalDefId) -> ReportRoot<'_> {
    if tcx
        .generics_of(local.to_def_id())
        .requires_monomorphization(tcx)
    {
        ReportRoot::Generic { local }
    } else {
        ReportRoot::Concrete {
            local,
            instance: Instance::mono(tcx, local.to_def_id()),
        }
    }
}

fn find_local_fn_by_path(tcx: TyCtxt<'_>, path: &str) -> Option<LocalDefId> {
    analyzable_local_fn_defs(tcx).find(|local| canonical_namespace(tcx, local.to_def_id()) == path)
}

fn public_local_fn_defs(tcx: TyCtxt<'_>) -> impl Iterator<Item = LocalDefId> + '_ {
    // Effective visibility, not declared: a `pub fn` in a private module is
    // not part of the public API unless something re-exports it, and
    // re-exports count (`is_exported`, not `is_directly_public`).
    analyzable_local_fn_defs(tcx)
        .filter(move |local| tcx.effective_visibilities(()).is_exported(*local))
}

fn analyzable_local_fn_defs(tcx: TyCtxt<'_>) -> impl Iterator<Item = LocalDefId> + '_ {
    tcx.hir_body_owners()
        .filter(move |local| matches!(tcx.def_kind(*local), DefKind::Fn | DefKind::AssocFn))
}
