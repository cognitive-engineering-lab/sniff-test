/// # Unsafe
/// * nn: ptr should be non null
fn foo(ptr: *const i32) {
  unsafe { *ptr; }
}

#[hocklorp::check_unsafe]
fn main() {
  let x = 1;
  foo(&raw const x);
}
