/// # Unsafe
/// * nn: ptr should be non null
fn foo(ptr: *const i32) -> i32 {
  unsafe { *ptr }
}

/// # Unsafe
/// * nn: ptr should be non null
fn bar(ptr: *const i32) -> i32 {
  foo(ptr)
}

#[hocklorp_attrs::check_unsafe]
fn main() {
  let x = 1;

  /// Safety:
  /// * nn: ptr expr must be on null
  bar(&raw const x)
}
