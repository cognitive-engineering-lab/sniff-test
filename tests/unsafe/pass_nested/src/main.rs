#![allow(unused_doc_comments)]

/// # Unsafe
/// * nn: ptr should be non null
unsafe fn foo(val: *const i32) -> i32 {
    unsafe { *val }
}

#[sniff_test_attrs::check_unsafe]
fn main() {
    let x = 1;

    unsafe {
        /// Safety:
        /// * nn: ptr expr must be on null
        foo(&raw const x);
    }
}
