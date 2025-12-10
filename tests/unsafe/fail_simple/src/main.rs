/// # Safety
/// * nn: ptr should be non null
unsafe fn foo(ptr: *const i32) -> i32 {
    unsafe { *ptr }
}

#[sniff_test_attrs::check_unsafe]
fn main() {
    let x = 1;
    unsafe {
        foo(&raw const x);
    }
}
