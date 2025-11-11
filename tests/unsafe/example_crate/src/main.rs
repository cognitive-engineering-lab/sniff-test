#![sniff_test_attrs::check_unsafe_pub]

/// # Safety
/// - non-null: ptr must be non-null
fn foo(ptr: *const i32) -> i32 {
    let a = baz(ptr);
    a + 2
}

pub fn baz(ptr: *const i32) -> i32 {
    unsafe { *ptr }
}

#[sniff_test_attrs::check_unsafe]
fn bar(ptr: *const i32) -> i32 {
    /// SAFETY:
    /// - non-null: i checked to make sure this is nn
    // if !ptr.is_null() {
    foo(ptr)
    // baz(ptr)
    // }
}

fn main() {
    let a = Some(3).unwrap();
    let x = 1;
    /// SAFETY: blah blah
    /// more doc comments
    unsafe {
        foo(&raw const x);
    }
}

// Notes from justus
// - instance safety for some traits
// - when it cant be done alwyas deny and just allow specific instances
