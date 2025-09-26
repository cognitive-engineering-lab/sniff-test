/// # Unsafe
/// - nonnn-nm: non null
/// - non-null: aligned
///   and ready for business
unsafe fn foo(ptr: *const i32) -> i32 {
    unsafe { *ptr }
}

/// # Unsafe
/// - nonnnnm: non null
/// - non-null: aligned
///   and ready for business
#[sniff_test_attrs::check_unsafe]
fn main() {
    let x = 1;

    unsafe {
        /// Safety:
        /// * nn-nn: ive done some check to make sure ptr isnt null
        /// * nn-n: ive done some check to make sure ptr isnt null
        foo(&raw const x);
    }
}
