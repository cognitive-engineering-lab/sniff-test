/// # Unsafe
/// * nn: ptr should be non null
unsafe fn foo(ptr: *const i32) -> i32 {
    unsafe { *ptr }
}

/// # Unsafe
/// * nn: ptr should be non null
fn bar(ptr: *const i32) -> i32 {
    /// Unsafetey:
    /// - non-null: this is non-null bc i checked...
    unsafe {
        foo(ptr)
    }
}

#[hocklorp_attrs::check_unsafe]
fn main() {
    let x = 1;

    /// Safety:
    /// * nn: ptr expr must be on null
    bar(&raw const x);
}
