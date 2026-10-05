#![allow(dead_code)]
#![cfg_attr(sniff_test, feature(register_tool), register_tool(sniff_test))]
#![cfg_attr(sniff_test, warn(sniff_test::panic))]

fn crate_warned() {
    panic!("crate");
}

#[cfg_attr(sniff_test, allow(sniff_test::panic))]
fn function_allowed() {
    panic!("allowed");
}

#[cfg_attr(sniff_test, deny(sniff_test::panic))]
mod denied {
    fn private_function() {
        panic!("module");
    }

    pub struct Holder;

    impl Holder {
        fn method(&self) {
            panic!("impl method");
        }
    }

    pub trait Trait {
        fn default_method(&self) {
            panic!("trait method");
        }
    }

    #[cfg_attr(sniff_test, allow(sniff_test::panic))]
    fn locally_allowed() {
        panic!("local override");
    }

    #[cfg_attr(sniff_test, warn(sniff_test::panic))]
    mod warned {
        fn nested_function() {
            panic!("nested override");
        }
    }
}

struct Outside;

#[cfg_attr(sniff_test, deny(sniff_test::panic))]
impl Outside {
    fn impl_scoped(&self) {
        panic!("impl scope");
    }
}

#[cfg_attr(sniff_test, deny(sniff_test::panic))]
trait OutsideTrait {
    fn trait_scoped(&self) {
        panic!("trait scope");
    }
}

#[cfg_attr(sniff_test, forbid(sniff_test::panic))]
mod forbidden {
    fn forbidden_function() {
        panic!("forbid scope");
    }
}
