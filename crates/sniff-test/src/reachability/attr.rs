//! Utilities for parsing our own `sniff_test_attr` annotation attributes.

use std::any::{Any, TypeId};

use rustc_hir::{Attribute, def_id::DefId};
use rustc_middle::ty::TyCtxt;

use crate::properties::{self, Property};

pub fn attrs_for(def_id: DefId, tcx: TyCtxt) -> Vec<SniffToolAttr> {
    get_sniff_tool_attrs(tcx.get_all_attrs(def_id))
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SniffToolAttr {
    CheckUnsafe,
    CheckPanics,
}

impl SniffToolAttr {
    fn try_from_string(string: &str) -> Option<Self> {
        println!("parsing from string {string:?}");
        match string {
            "check_unsafe" => Some(Self::CheckUnsafe),
            "check_panics" => Some(Self::CheckPanics),
            _ => None,
        }
    }

    pub fn matches_property<P: Property>(self) -> bool {
        TypeId::of::<P>() == self.property()
    }

    pub fn property(self) -> TypeId {
        match self {
            Self::CheckPanics => properties::PanicProperty.type_id(),
            Self::CheckUnsafe => properties::SafetyProperty.type_id(),
        }
    }
}

pub fn get_sniff_tool_attrs(attrs: &[Attribute]) -> Vec<SniffToolAttr> {
    attrs
        .iter()
        .filter_map(|attr| {
            let Attribute::Unparsed(box item) = attr else {
                return None;
            };

            let str_segs = item
                .path
                .segments
                .iter()
                .map(rustc_span::Ident::as_str)
                .collect::<Box<[_]>>();

            // TODO: this might be hacky bc we're comparing strings...
            // No actually it seems to work fine.
            match str_segs {
                box ["sniff_tool", b] => SniffToolAttr::try_from_string(b),
                _ => None,
            }
        })
        .collect::<Vec<_>>()
}
