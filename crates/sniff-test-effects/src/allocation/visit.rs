//! Heap allocation seeds from calls to allocator entry points.

use rustc_hir::LangItem;
use rustc_hir::def_id::DefId;
use rustc_hir::definitions::DefPathData;
use rustc_middle::middle::codegen_fn_attrs::CodegenFnAttrFlags;
use rustc_middle::mir::{Location, TerminatorKind};
use rustc_middle::ty::{TyCtxt, TyKind};
use rustc_span::Symbol;
use sniff_test_core::effects::visit::{
    MirEffectCx, MirEffectPass, PreliminaryMirEffectSeed, PreliminaryMirEffectSource,
};

use super::AllocationOperation;

pub struct AllocationInvocationPass;

impl MirEffectPass for AllocationInvocationPass {
    fn check_body(&mut self, cx: MirEffectCx<'_>) -> Vec<PreliminaryMirEffectSeed> {
        cx.body()
            .basic_blocks
            .iter_enumerated()
            .filter_map(|(block, data)| {
                let (TerminatorKind::Call { func, .. } | TerminatorKind::TailCall { func, .. }) =
                    &data.terminator().kind
                else {
                    return None;
                };
                let TyKind::FnDef(def_id, args) = *cx.operand_ty(func).kind() else {
                    return None;
                };
                let callee = cx
                    .resolve_callable_instance(def_id, args)
                    .map_or(def_id, |instance| instance.def_id());
                is_allocation_entry(cx, callee).then(|| PreliminaryMirEffectSeed {
                    location: Location {
                        block,
                        statement_index: data.statements.len(),
                    },
                    kind: AllocationOperation::HeapAllocation.into(),
                    source: PreliminaryMirEffectSource::Invocation {
                        requires_documented_obligation: false,
                    },
                    suppress_in_compiler_context: false,
                })
            })
            .collect()
    }
}

fn is_allocation_entry(cx: MirEffectCx<'_>, callee: DefId) -> bool {
    let tcx = cx.tcx();
    // An allocator implementation can call another allocator as its backend.
    // The call into the implementation is already the source for that request.
    if allocator_method(cx, cx.instance().def_id()) {
        return false;
    }
    if tcx
        .codegen_fn_attrs(callee)
        .flags
        .intersects(CodegenFnAttrFlags::ALLOCATOR | CodegenFnAttrFlags::ALLOCATOR_ZEROED)
    {
        return true;
    }

    allocator_method(cx, callee)
}

fn allocator_method(cx: MirEffectCx<'_>, callee: DefId) -> bool {
    let tcx = cx.tcx();
    let declaration = tcx.trait_item_of(callee).unwrap_or(callee);
    let Some(trait_id) = tcx.trait_of_assoc(declaration) else {
        return false;
    };
    let method = tcx.item_name(declaration);
    if is_core_trait(tcx, trait_id, &["alloc", "Allocator"]) {
        !is_standard_global_allocator(tcx, callee)
            && ["allocate", "allocate_zeroed"]
                .iter()
                .any(|name| method == Symbol::intern(name))
    } else if is_core_trait(tcx, trait_id, &["alloc", "global", "GlobalAlloc"]) {
        ["alloc", "alloc_zeroed"]
            .iter()
            .any(|name| method == Symbol::intern(name))
    } else {
        false
    }
}

fn is_core_trait(tcx: TyCtxt<'_>, trait_id: DefId, segments: &[&str]) -> bool {
    // These traits have no diagnostic or language item; match their definition
    // paths within core rather than a rendered path or the caller's import name.
    let Some(core_crate) = tcx.lang_items().sized_trait().map(|id| id.krate) else {
        return false;
    };
    let path = tcx.def_path(trait_id);
    trait_id.krate == core_crate
        && path.data.len() == segments.len()
        && path
            .data
            .iter()
            .zip(segments)
            .all(|(part, name)| {
                matches!(part.data, DefPathData::TypeNs(symbol) if symbol == Symbol::intern(name))
            })
}

fn is_standard_global_allocator(tcx: TyCtxt<'_>, callee: DefId) -> bool {
    tcx.impl_of_assoc(callee).is_some_and(|impl_id| {
        let self_ty = tcx.type_of(impl_id).instantiate_identity().skip_normalization();
        matches!(self_ty.kind(), TyKind::Adt(adt, _) if tcx.is_lang_item(adt.did(), LangItem::GlobalAlloc))
    })
}
