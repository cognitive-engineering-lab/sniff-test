use rustc_hir::def_id::{DefId, LocalDefId};
use rustc_middle::ty::TyCtxt;

use crate::reachability::attr::{self, SniffToolAttr};

pub fn local_entry_points(tcx: TyCtxt) -> impl Iterator<Item = LocalDefId> {
    // global_annotations(tcx);
    if false {
        todo!()
    } else {
        annotated_local_entry_points(tcx)
    }
}

pub fn global_annotations(tcx: TyCtxt) -> bool {
    for attr in tcx.hir_krate_attrs() {
        println!("attr is {attr:?}");
    }
    todo!()
}

fn annotated_local_entry_points(tcx: TyCtxt) -> impl Iterator<Item = LocalDefId> {
    tcx.hir_body_owners()
        .filter(move |item| is_entry_point(tcx, item.to_def_id()))
}

fn is_entry_point(tcx: TyCtxt, item: DefId) -> bool {
    attr::attrs_for(item, tcx).is_some_and(|attr| match attr {
        SniffToolAttr::CheckUnsafe => true,
    })
}
