#![allow(unused_doc_comments)]
extern crate sniff_test_attrs;

// This shouldn't be allowed, but a buggy implementation could feasibly accidentally allow it.

#[sniff_test_attrs::check_unsafe]
/// SAFETY: ...
fn main() {
    let x = 10;
    let ptr = &raw const x;
    unsafe { deref(ptr) };
}

/// # Safety
/// `ptr` must be aligned, non-null, etc.
unsafe fn deref(ptr: *const i32) -> i32 {
    unsafe { *ptr }
}
