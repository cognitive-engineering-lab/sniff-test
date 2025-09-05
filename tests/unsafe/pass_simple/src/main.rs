/// # Unsafe
/// * nn: ptr should be non null
fn foo(ptr: *const i32) -> i32 {
  unsafe { *ptr }
}

#[hocklorp_attrs::check_unsafe]
fn main() {
  let x = 1;

  /// Safety:
  /// * nn: ptr expression must be non null
  foo(&raw const x);
}
