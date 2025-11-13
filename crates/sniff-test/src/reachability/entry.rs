use std::collections::{BTreeSet, HashSet};

use rustc_hir::{
    def::DefKind,
    def_id::{DefId, LocalDefId},
};
use rustc_middle::ty::TyCtxt;

use crate::{
    properties::Property,
    reachability::attrs::{self, SniffToolAttr},
};

pub fn analysis_entry_points<P: Property>(tcx: TyCtxt) -> Vec<LocalDefId> {
    // TODO: should use a btree rather than a hash set here so that we'll have a consistent order
    // but local def ids aren't ord so this will likely require an upstream changes.
    let mut entry_points = HashSet::new();

    if let Some(global_annotation) = find_global_annotation::<P>(tcx) {
        if global_annotation.just_check_pub {
            // A `_pub` annotation can also be used in conjunction with other non-pub functions,
            // so we have to continue looking for annotated local defs.
            entry_points.extend(all_pub_local_fn_defs(tcx));
        } else {
            // This is everything we can possibly analyzing the local crate, so just return that.
            return all_local_fn_defs(tcx).collect();
        }
    }

    entry_points.extend(annotated_local_defs::<P>(tcx));
    entry_points.into_iter().collect()
}

fn find_global_annotation<P: Property>(tcx: TyCtxt) -> Option<GlobalAnnotation> {
    let property_annots =
        attrs::get_sniff_tool_attrs(tcx.hir_krate_attrs(), &SniffToolAttr::try_from_string_pub)
            .into_iter()
            .filter(|(attr, _)| SniffToolAttr::matches_property::<P>(*attr))
            .collect::<Vec<_>>();

    if property_annots.is_empty() {
        return None;
    }

    // TODO: render error here if we have conflicting annotations...
    let box [(_attr, just_check_pub)] = property_annots.into_boxed_slice() else {
        panic!(
            "conflicting global for the {:?} property",
            P::property_name()
        );
    };
    Some(GlobalAnnotation { just_check_pub })
}

struct GlobalAnnotation {
    just_check_pub: bool,
}

fn all_local_fn_defs(tcx: TyCtxt) -> impl Iterator<Item = LocalDefId> {
    tcx.hir_body_owners().filter(is_def_analyzeable(tcx))
}

fn is_def_analyzeable(tcx: TyCtxt) -> impl Fn(&LocalDefId) -> bool {
    move |local| {
        let span = tcx.def_span(*local);
        log::debug!("looking at owner {local:?} @ {span:?}");
        match tcx.def_kind(*local) {
            DefKind::Fn => true,
            // For context, zerocopy has all of these, but I don't think we want to analyze them...
            // Don't want anything to fall through the cracks though, so left as todo.
            // TODO: should we be handling more here?? Or just be dumb like racerd
            // DefKind::Impl { .. } | DefKind::AssocConst => false,
            // unhandled => todo!("don't know what to do with defkind {unhandled:?} yet..."),
            _ => false,
        }
    }
}

fn all_pub_local_fn_defs(tcx: TyCtxt) -> impl Iterator<Item = LocalDefId> {
    all_local_fn_defs(tcx).filter(move |owner| tcx.visibility(*owner).is_public())
}

fn annotated_local_defs<P: Property>(tcx: TyCtxt) -> impl Iterator<Item = LocalDefId> {
    tcx.hir_body_owners()
        .filter(move |item| is_entry_point::<P>(tcx, item.to_def_id()))
}

fn is_entry_point<P: Property>(tcx: TyCtxt, item: DefId) -> bool {
    attrs::attrs_for(item, tcx)
        .into_iter()
        .any(SniffToolAttr::matches_property::<P>)
}
