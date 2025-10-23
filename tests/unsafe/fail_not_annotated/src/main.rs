/// # Unsafe
/// - css: css
fn foo(ptr: *const i32) -> i32 {
    let a = unsafe { *ptr };
    // std::mem::drop(ptr);
    a + 2
}

/// # Unsafe
/// - css: css
fn foo2(ptr: *const i32) -> i32 {
    let a = unsafe { *ptr };
    a + 2
}

fn bar(ptr: *const i32) -> i32 {
    let a = foo(ptr);
    foo2(ptr) + unsafe { *ptr } + foo(ptr) + a
}

#[sniff_test_attrs::check_unsafe]
fn main() {
    let x = 1;
    /// Hello
    bar(&raw const x);
}

// - instance safety for some traits
// - when it cant be done alwyas deny and just allow specific instances
