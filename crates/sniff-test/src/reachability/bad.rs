//! Finds the 'bad' functions that should be annotated

use crate::annotations::{self, DefAnnotation, parse_fn_def};
use crate::properties::Property;
use crate::reachability::LocallyReachable;
use std::collections::HashMap;
use std::ops::Try;

use crate::utils::MultiEmittable;
use rustc_hir::def_id::{DefId, DefPathHash};
use rustc_middle::ty::TyCtxt;
use rustc_public::mir::Safety;
use rustc_public::ty::FnDef;
use rustc_span::source_map::Spanned;
use rustc_span::{ErrorGuaranteed, Span};

#[derive(Debug)]
pub struct CallsWObligations {
    pub call_to: DefId,
    pub w_annotation: DefAnnotation,
    pub from_spans: Vec<Span>,
}

fn call_has_obligations<P: Property>(
    tcx: TyCtxt,
    property: P,
) -> impl Fn((&DefId, &Vec<Span>)) -> Option<CallsWObligations> {
    move |(to_def_id, from_spans)| {
        let annotation = parse_fn_def(tcx, *to_def_id, property)?;

        if annotation.creates_obligation() {
            Some(CallsWObligations {
                call_to: *to_def_id,
                w_annotation: annotation,
                from_spans: from_spans.clone(),
            })
        } else {
            None
        }
    }
}

pub fn find_calls_w_obligations<P: Property>(
    tcx: TyCtxt,
    locally_reachable: &LocallyReachable,
    property: P,
) -> impl Iterator<Item = CallsWObligations> {
    locally_reachable
        .calls_to
        .iter()
        .filter_map(call_has_obligations(tcx, property))
}
