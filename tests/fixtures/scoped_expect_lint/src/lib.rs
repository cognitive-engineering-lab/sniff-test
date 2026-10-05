#![allow(dead_code)]
#![cfg_attr(sniff_test, feature(register_tool), register_tool(sniff_test))]
#![cfg_attr(sniff_test, expect(sniff_test::safety))]

#[cfg_attr(sniff_test, expect(sniff_test::panic))]
mod fulfilled {
    fn first() {
        panic!("first");
    }

    fn second() {
        panic!("second");
    }
}

#[cfg_attr(sniff_test, expect(sniff_test::panic))]
mod unfulfilled {
    fn safe() {}
}

#[cfg_attr(sniff_test, expect(sniff_test::panic))]
mod overridden {
    #[cfg_attr(sniff_test, allow(sniff_test::panic))]
    fn locally_allowed() {
        panic!("override");
    }
}
