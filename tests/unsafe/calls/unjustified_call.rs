extern crate sniff_test_attrs;

/// # Unsafe
/// * nn: ptr should be non null
fn foo(ptr: *const i32) -> i32 {
    unsafe { *ptr }
}

#[sniff_test_attrs::check_unsafe]
fn main() {
    let x = 1;
    foo(&raw const x);
}
