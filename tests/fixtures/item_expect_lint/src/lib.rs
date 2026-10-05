#![allow(dead_code)]
#![cfg_attr(sniff_test, feature(register_tool), register_tool(sniff_test))]

#[cfg_attr(sniff_test, expect(sniff_test::panic))]
pub fn div(left: u64, right: u64) -> u64 {
    left / right
}

#[cfg_attr(sniff_test, expect(sniff_test::safety))]
pub fn read(ptr: *const u8) -> u8 {
    unsafe { *ptr }
}

#[cfg_attr(sniff_test, expect(sniff_test::panic))]
pub fn no_panic() -> u64 {
    1
}

#[cfg_attr(sniff_test, expect(sniff_test::panic))]
pub fn justified_div(left: u64, right: u64) -> u64 {
    // PANIC: the caller guarantees a nonzero divisor.
    left / right
}

/// # Panics
///
/// Panics if `right` is zero.
#[cfg_attr(sniff_test, expect(sniff_test::panic))]
pub fn documented_div(left: u64, right: u64) -> u64 {
    left / right
}

#[expect(unused_variables)]
pub fn rustc_expected(unused: u64) {}
