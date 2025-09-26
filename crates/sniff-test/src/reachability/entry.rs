use rustc_hir::Attribute;
use rustc_middle::ty::TyCtxt;
use rustc_public::{CrateItem, ty::FnDef};
use rustc_span::symbol::Ident;

pub fn filter_entry_points(tcx: TyCtxt, items: &[CrateItem]) -> Vec<FnDef> {
    items
        .iter()
        .filter_map(|item| is_entry_point(tcx, item))
        .collect::<Vec<_>>()
}

fn is_entry_point(tcx: TyCtxt, item: &CrateItem) -> Option<FnDef> {
    // Is a function definition
    let Some((def, _generics)) = item.ty().kind().fn_def() else {
        return None;
    };

    println!("looking at fn def {def:?}");
    // Has an annotation
    let internal = rustc_public::rustc_internal::internal(tcx, item);

    let b = tcx.get_all_attrs(internal);
    let s = get_sniff_tool_attr(b);
    println!("s is {s:?}");

    Some(def)
}

#[derive(Debug)]
enum SniffToolAttr {
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
    println!("sniff_tool {:?}", sniff_tool);

    match sniff_tool {
        box [attr_name] => SniffToolAttr::try_from_string(attr_name),
        box [] => None,
        box [_first, _second, ..] => {
            panic!("multiple sniff test attrs on the same jawn {sniff_tool:?}")
        }
    }
}
