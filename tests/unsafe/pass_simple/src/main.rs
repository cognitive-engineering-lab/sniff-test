/// # Safety
/// - non-null: ptr must be non-null
/// - aligned: ptr must be aligned for an i32
unsafe fn foo(ptr: *const i32) -> i32 {
    unsafe { *ptr }
}

#[sniff_test_attrs::check_unsafe]
fn main() {
    let x = 1;

    unsafe {
        /// Safety:
        /// * non-null: a pointer that comes from a reference is trivially non-null
        /// * aligned: a pointer that comes from a reference is trivially aligned
        foo(&raw const x);
    }
}
