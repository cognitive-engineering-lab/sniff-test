//! Finds the 'bad' functions that should be annotated

use crate::annotations::{DefAnnotation, parse_fn_def, toml::TomlAnnotation};
use crate::properties::Property;
use crate::reachability::LocallyReachable;

use rustc_hir::def_id::DefId;
use rustc_middle::ty::TyCtxt;
use rustc_span::Span;

#[derive(Debug)]
pub struct CallsWObligations {
    pub call_to: DefId,
    pub _w_annotation: DefAnnotation,
    pub from_spans: Vec<Span>,
}

fn call_has_obligations<P: Property>(
    tcx: TyCtxt,
    toml_annotations: &TomlAnnotation,
    property: P,
) -> impl Fn((&DefId, &Vec<Span>)) -> Option<CallsWObligations> {
    move |(to_def_id, from_spans)| {
        let annotation = parse_fn_def(tcx, toml_annotations, *to_def_id, property)?;
        if annotation.creates_obligation() {
            Some(CallsWObligations {
                call_to: *to_def_id,
                _w_annotation: annotation,
                from_spans: from_spans.clone(),
            })
        } else {
            None
        }
    }
}

pub fn find_calls_w_obligations<P: Property>(
    tcx: TyCtxt,
    toml_annotations: &TomlAnnotation,
    locally_reachable: &LocallyReachable,
    property: P,
) -> impl Iterator<Item = CallsWObligations> {
    locally_reachable
        .calls_to
        .iter()
        .filter_map(call_has_obligations(tcx, toml_annotations, property))
}
