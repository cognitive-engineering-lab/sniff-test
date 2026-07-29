//! Selection of current-crate functions that should produce reports.
//!
//! Report roots are not the whole reachability graph. They are the starting
//! functions sniff-test analyzes when deciding which effect paths to report.
//! Generic roots are analyzed structurally with identity generic arguments.

use std::collections::HashSet;
use std::ops::Range;

use reachability::ReachabilityRoot;
use rustc_hir::def::DefKind;
use rustc_hir::def_id::{DefId, LocalDefId};
use rustc_middle::ty::{Instance, TyCtxt};
use serde::Serialize;

use crate::config::{AnalysisConfig, ReportRootSet};
use crate::namespace::canonical_namespace;

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
}

#[derive(Debug, Clone, Copy)]
pub enum ReportRoot<'tcx> {
    /// Monomorphic function that can be analyzed immediately.
    Concrete { instance: Instance<'tcx> },
    /// Generic function analyzed structurally with identity generic arguments.
    Generic { local: LocalDefId },
}

impl<'tcx> ReportRoot<'tcx> {
    #[must_use]
    pub fn def_id(self) -> DefId {
        match self {
            Self::Concrete { instance } => instance.def_id(),
            Self::Generic { local } => local.to_def_id(),
        }
    }

    #[must_use]
    pub fn reachability_root(self) -> ReachabilityRoot<'tcx> {
        match self {
            Self::Concrete { instance, .. } => ReachabilityRoot::Instance(instance),
            Self::Generic { local } => ReachabilityRoot::LocalBody(local),
        }
    }

    #[must_use]
    pub fn kind(self) -> ReportRootKind {
        match self {
            Self::Concrete { .. } => ReportRootKind::Concrete,
            Self::Generic { .. } => ReportRootKind::Generic,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReportRootKind {
    Concrete,
    Generic,
}

#[must_use]
pub fn select_report_roots<'tcx>(
    tcx: TyCtxt<'tcx>,
    analysis_config: &AnalysisConfig,
) -> ReportRootSelection<'tcx> {
    let mut roots = HashSet::new();

    match analysis_config.report_roots.get_ref() {
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
                    Some(local) => {
                        roots.insert(local);
                    }
                    None => {
                        missing_roots.push(MissingReportRoot {
                            path: configured_root.path().to_owned(),
                            source_span: configured_root.source_span(),
                        });
                    }
                }
            }

            return sorted_selection(tcx, roots, missing_roots);
        }
    }

    sorted_selection(tcx, roots, Vec::new())
}

fn sorted_selection(
    tcx: TyCtxt<'_>,
    roots: HashSet<LocalDefId>,
    missing_roots: Vec<MissingReportRoot>,
) -> ReportRootSelection<'_> {
    let mut roots = roots
        .into_iter()
        .map(|local| report_root(tcx, local))
        .collect::<Vec<_>>();

    roots.sort_by(|left, right| {
        canonical_namespace(tcx, left.def_id()).cmp(&canonical_namespace(tcx, right.def_id()))
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
