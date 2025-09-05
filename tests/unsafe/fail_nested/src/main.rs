/// # Unsafe
/// * nn: ptr should be non null
fn foo(ptr: *const i32) -> i32 {
    unsafe { *ptr }
}

fn bar(ptr: *const i32) -> i32 {
    foo(ptr)
}

#[hocklorp_attrs::check_unsafe]
fn main() {
    let x = 1;
    bar(&raw const x)
}
