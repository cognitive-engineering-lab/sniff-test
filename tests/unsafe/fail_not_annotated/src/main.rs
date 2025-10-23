/// # Unsafe
/// - non-null: ptr is non-null
/// - aligned: ptr is aligned for a i32
fn foo(ptr: *const i32) -> i32 {
    let a = unsafe { *ptr };
    // std::mem::drop(ptr);
    a + 2
}

fn bar(ptr: *const i32) -> i32 {
    /// SAFETY:
    /// - non-null: i have checked this is non-null
    /// - aligned: i have also checked it is aligned
    foo(ptr)
}

#[sniff_test_attrs::check_unsafe]
fn main() {
    let x = 1;
    /// Hello
    bar(&raw const x);
}

// - instance safety for some traits
// - when it cant be done alwyas deny and just allow specific instances
