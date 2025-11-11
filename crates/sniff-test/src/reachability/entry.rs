use rustc_hir::def_id::{DefId, LocalDefId};
use rustc_middle::ty::TyCtxt;

use crate::{
    properties::Property,
    reachability::attr::{self, SniffToolAttr},
};

pub fn local_entry_points<P: Property>(tcx: TyCtxt) -> Vec<LocalDefId> {
    let globally_annotated = attr::get_sniff_tool_attrs(tcx.hir_krate_attrs())
        .into_iter()
        .any(SniffToolAttr::matches_property::<P>);

    if globally_annotated {
        println!("GLOBALLY ANNOTATED FOR {}", P::name());
        let a = all_local_defs(tcx).collect();
        println!("all local defs {a:?}");
        a
    } else {
        println!("locally annotated for {}", P::name());
        todo!();
        annotated_local_defs::<P>(tcx).collect()
    }
}

fn all_local_defs(tcx: TyCtxt) -> impl Iterator<Item = LocalDefId> {
    tcx.hir_body_owners()
}

fn annotated_local_defs<P: Property>(tcx: TyCtxt) -> impl Iterator<Item = LocalDefId> {
    tcx.hir_body_owners()
        .filter(move |item| is_entry_point::<P>(tcx, item.to_def_id()))
}

fn is_entry_point<P: Property>(tcx: TyCtxt, item: DefId) -> bool {
    attr::attrs_for(item, tcx)
        .into_iter()
        .any(SniffToolAttr::matches_property::<P>)
}
