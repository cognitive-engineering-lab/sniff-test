#![allow(unused_doc_comments)]
#![deny(clippy::undocumented_unsafe_blocks)]
extern crate sniff_test_attrs;

// This behavior is NOT allowed by the clippy lint as, in theory, each unsafe block should
// only have a single operation with a single comment on the block. However, we're allowing it for now,
// disabling it could be a TODO: for the future.

#[sniff_test_attrs::check_unsafe]
fn main() {
    let x = 10;
    let ptr = &raw const x;
    unsafe {
        /// SAFETY: ...
        deref(ptr);
    }
}

/// # Safety
/// `ptr` must be aligned, non-null, etc.
unsafe fn deref(ptr: *const i32) -> i32 {
    unsafe { *ptr }
}
