#![sniff_tool::check_unsafe_pub]

/// # Safety
/// 
fn foo(ptr: *const i32) -> i32 {
    0
}

/// # Saety
///     I've checked ptr is non-null and aligned
pub fn baz(ptr: *const i32) -> i32 {
    /// SAFETY: ptr is non null I've checked
    unsafe { *ptr }
}

#[sniff_test_attrs::check_unsafe]
fn bar(ptr: *const i32) -> i32 {

    unsafe {
        baz(ptr);
    }
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
