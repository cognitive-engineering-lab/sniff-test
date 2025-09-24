#![allow(unused_doc_comments)]

/// # Unsafe
/// * nn: ptr should be non null
unsafe fn foo(ptr: *const i32) -> i32 {
    unsafe { ptr }
}

unsafe fn foo2(ptr: *const i32) -> i32 {
    unsafe { ptr }
}

/// # Unsafe
/// * nn: ptr should be non null
unsafe fn bar(ptr: *const i32) -> i32 {
    /// SAFETY:
    /// - nn: this is non-null bc i checked...
    unsafe {
        foo(ptr)
    }
}

#[sniff_test_attrs::check_unsafe]
fn main() {
    let x = 1;

    /// Safety:
    /// * nn: ptr expr must be on null
    unsafe {
        bar(&raw const x);
    }
}
