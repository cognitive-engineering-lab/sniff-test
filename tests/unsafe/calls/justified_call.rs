extern crate sniff_test_attrs;

/// # Unsafe
/// * nn: ptr should be non null
fn foo(ptr: *const i32) -> i32 {
    unsafe { *ptr }
}

#[sniff_test_attrs::check_unsafe]
fn main() {
    let x = 1;
    /// SAFETY:
    /// - nn: pointers from references are trivially non-null
    foo(&raw const x);
}
