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

use crate::config::{PanicConfig, ReportRootSet};
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
    /// Fully qualified function path from `[panics].report-roots`.
    pub path: String,
    /// Byte range of the TOML string value in the sniff-test manifest.
    pub source_span: Range<usize>,
}

#[derive(Debug, Clone, Copy)]
pub enum ReportRoot<'tcx> {
    /// Monomorphic function that can be analyzed immediately.
    Concrete {
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
pub fn select_panic_report_roots<'tcx>(
    tcx: TyCtxt<'tcx>,
    config: &PanicConfig,
) -> ReportRootSelection<'tcx> {
    let crate_name = tcx.crate_name(LOCAL_CRATE).to_string();
    if config.ignores_namespace(&crate_name) {
        return ReportRootSelection {
            roots: Vec::new(),
            missing_roots: Vec::new(),
        };
    }

    let mut roots = HashSet::new();

    match &config.report_roots {
        ReportRootSet::Public => {
            roots.extend(public_local_fn_defs(tcx));
        }
        ReportRootSet::All => {
            roots.extend(analyzable_local_fn_defs(tcx));
        }
        ReportRootSet::Explicit(configured_roots) => {
            let mut missing_roots = Vec::new();
            for configured_root in configured_roots {
                if let Some(local) = find_local_fn_by_path(tcx, configured_root.path()) {
                    roots.insert(local);
                } else {
                    missing_roots.push(MissingReportRoot {
                        path: configured_root.path().to_owned(),
                        source_span: configured_root.source_span(),
                    });
                }
            }

            return sorted_selection(tcx, config, roots, missing_roots);
        }
    }

    sorted_selection(tcx, config, roots, Vec::new())
}

fn sorted_selection<'tcx>(
    tcx: TyCtxt<'tcx>,
    config: &PanicConfig,
    roots: HashSet<LocalDefId>,
    missing_roots: Vec<MissingReportRoot>,
) -> ReportRootSelection<'tcx> {
    let mut roots = roots
        .into_iter()
        .filter(|local| !config.ignores_namespace(&canonical_namespace(tcx, local.to_def_id())))
        .map(|local| report_root(tcx, local))
        .collect::<Vec<_>>();

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
    analyzable_local_fn_defs(tcx).filter(move |local| tcx.visibility(*local).is_public())
}

fn analyzable_local_fn_defs(tcx: TyCtxt<'_>) -> impl Iterator<Item = LocalDefId> + '_ {
    tcx.hir_body_owners()
        .filter(move |local| matches!(tcx.def_kind(*local), DefKind::Fn | DefKind::AssocFn))
}
