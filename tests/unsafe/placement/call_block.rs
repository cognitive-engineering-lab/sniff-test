#![allow(unused_doc_comments)]
extern crate sniff_test_attrs;

// This kind of documentation is allowed by [the clippy lint](https://rust-lang.github.io/rust-clippy/master/index.html?search=undocumented_unsafe_blocks),
// so we should accept it too.

#[sniff_test_attrs::check_unsafe]
fn main() {
    let x = 10;
    let ptr = &raw const x;
    /// SAFETY: ...
    unsafe {
        deref(ptr)
    };
}

/// # Safety
/// `ptr` must be aligned, non-null, etc.
unsafe fn deref(ptr: *const i32) -> i32 {
    unsafe { *ptr }
}
