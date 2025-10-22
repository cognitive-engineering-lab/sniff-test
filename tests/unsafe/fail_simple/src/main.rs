/// # Unsafe
/// * nn: ptr should be non null
#[sniff_test_attrs::check_unsafe]
fn foo(ptr: *const i32) -> i32 {
    unsafe { *ptr }
}

fn main() {
    let x = 1;
    foo(&raw const x);
}
