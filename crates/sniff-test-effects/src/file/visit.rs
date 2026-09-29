//! File mutation seeds at the calls that perform writes, creation, truncation, or deletion.

use rustc_hir::def_id::DefId;
use rustc_middle::mir::{Location, TerminatorKind};
use rustc_middle::ty::{TyCtxt, TyKind};
use rustc_span::Symbol;
use sniff_test_core::effects::visit::{
    MirEffectCx, MirEffectPass, PreliminaryMirEffectSeed, PreliminaryMirEffectSource,
};

use super::FileOperation;

pub struct FileMutationPass;

impl MirEffectPass for FileMutationPass {
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
                let operation = file_operation(cx.tcx(), callee)?;
                Some(PreliminaryMirEffectSeed {
                    location: Location {
                        block,
                        statement_index: data.statements.len(),
                    },
                    kind: operation.into(),
                    source: PreliminaryMirEffectSource::Invocation {
                        requires_documented_obligation: false,
                    },
                    suppress_in_compiler_context: false,
                })
            })
            .collect()
    }
}

fn file_operation(tcx: TyCtxt<'_>, callee: DefId) -> Option<FileOperation> {
    if tcx.crate_name(callee.krate) != Symbol::intern("std") {
        return None;
    }

    match tcx.def_path_str(callee).as_str() {
        // The generic helper's inner std body does not expose its File::create
        // call as an effect source in the current reachability artifact.
        "std::fs::write" => return Some(FileOperation::Write),
        "std::fs::File::create" | "std::fs::File::create_new" => {
            return Some(FileOperation::Create);
        }
        "std::fs::File::set_len" => return Some(FileOperation::Truncate),
        "std::fs::remove_file" => return Some(FileOperation::Delete),
        _ => {}
    }

    let declaration = tcx.trait_item_of(callee)?;
    let trait_id = tcx.trait_of_assoc(declaration)?;
    if tcx.def_path_str(trait_id) != "std::io::Write" {
        return None;
    }
    if !["write", "write_vectored"]
        .iter()
        .any(|method| tcx.item_name(declaration) == Symbol::intern(method))
    {
        return None;
    }
    let impl_id = tcx.impl_of_assoc(callee)?;
    let self_ty = tcx
        .type_of(impl_id)
        .instantiate_identity()
        .skip_normalization();
    let file_ty = match self_ty.kind() {
        TyKind::Ref(_, inner, _) => *inner,
        _ => self_ty,
    };
    matches!(file_ty.kind(), TyKind::Adt(adt, _) if tcx.def_path_str(adt.did()) == "std::fs::File")
        .then_some(FileOperation::Write)
}
