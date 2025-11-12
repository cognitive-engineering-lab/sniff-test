/// # Unsafe
/// * nn: ptr should be non null
fn foo(ptr: *const i32) -> i32 {
    let a = unsafe { *ptr };
    a + 2
}

fn bar(ptr: *const i32) -> i32 {
    foo(ptr)
}

#[sniff_test_attrs::check_unsafe]
fn main() {
    let x = 1;
    bar(&raw const x);
}
