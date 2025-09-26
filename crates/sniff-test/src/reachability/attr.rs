//! Utilities for parsing our own `sniff_test_attr` annotation attributes.

use rustc_hir::{Attribute, def_id::DefId};
use rustc_middle::ty::TyCtxt;

pub fn attrs_for(def_id: DefId, tcx: TyCtxt) -> Option<SniffToolAttr> {
    get_sniff_tool_attr(tcx.get_all_attrs(def_id))
}

#[derive(Debug)]
pub enum SniffToolAttr {
    CheckUnsafe,
}

impl SniffToolAttr {
    fn try_from_string(string: &str) -> Option<Self> {
        match string {
            "check_unsafe" => Some(Self::CheckUnsafe),
            _ => None,
        }
    }
}

fn get_sniff_tool_attr(attrs: &[Attribute]) -> Option<SniffToolAttr> {
    let sniff_tool = attrs
        .iter()
        .filter_map(|attr| {
            let Attribute::Unparsed(box item) = attr else {
                return None;
            };

            // TODO: this might be hacky bc we're comparing strings...
            match item
                .path
                .segments
                .iter()
                .map(|segment| segment.as_str())
                .collect::<Box<[_]>>()
            {
                box ["sniff_tool", b] => Some(b),
                _ => None,
            }
        })
        .collect::<Box<[_]>>();

    match sniff_tool {
        box [] => None,
        box [attr_name] => SniffToolAttr::try_from_string(attr_name),
        box [_first, _second, ..] => {
            panic!("multiple sniff test attrs on the same jawn {sniff_tool:?}")
        }
    }
}
