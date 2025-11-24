#![allow(unused_doc_comments)]
extern crate sniff_test_attrs;

#[sniff_test_attrs::check_unsafe]
fn main() {
    let x = 10;
    let ptr = &raw const x;
    /// SAFETY: ...
    let _ = unsafe { deref(ptr) };
}

/// # Safety
/// `ptr` must be aligned, non-null, etc.
unsafe fn deref(ptr: *const i32) -> i32 {
    unsafe { *ptr }
}
