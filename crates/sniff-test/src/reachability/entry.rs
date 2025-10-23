
use rustc_hir::def_id::{DefId, LocalDefId};
use rustc_middle::ty::TyCtxt;

use crate::reachability::attr::{self, SniffToolAttr};

// pub fn filter_entry_points(tcx: TyCtxt, items: &[FnDef]) -> Vec<FnDef> {
//     items
//         .into_iter()
//         .filter(|item| is_entry_point(tcx, **item))
//         .copied()
//         .collect::<Vec<_>>()
// }

pub fn annotated_local_entry_points(tcx: TyCtxt) -> impl Iterator<Item = LocalDefId> {
    tcx.hir_body_owners()
        .filter(move |item| is_entry_point(tcx, item.to_def_id()))
}

fn is_entry_point(tcx: TyCtxt, item: DefId) -> bool {
    attr::attrs_for(item, tcx).is_some_and(|attr| match attr {
        SniffToolAttr::CheckUnsafe => true,
    })
}
