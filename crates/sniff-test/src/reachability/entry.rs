use rustc_middle::ty::TyCtxt;
use rustc_public::{CrateItem, ty::FnDef};

use crate::reachability::attr::{self, SniffToolAttr};

pub fn filter_entry_points(tcx: TyCtxt, items: &[FnDef]) -> Vec<FnDef> {
    items
        .iter()
        .filter(|item| is_entry_point(tcx, item))
        .cloned()
        .collect::<Vec<_>>()
}

fn is_entry_point(tcx: TyCtxt, item: &FnDef) -> bool {
    let internal = rustc_public::rustc_internal::internal(tcx, item.0);

    attr::attrs_for(internal, tcx).map_or(false, |attr| match attr {
        SniffToolAttr::CheckUnsafe => true,
    })
}
