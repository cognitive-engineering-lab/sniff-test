

/// # Usage
/// - nonnn: non null
/// - non-null: aligned
///   and ready for business
unsafe fn foo(ptr: *const i32) -> i32 {
  unsafe { *ptr }
}

#[hocklorp_attrs::check_unsafe]
fn main() {
  let x = 1;

  // / Safety:
  // / * nn: ive done some check to make sure ptr isnt null
  unsafe { foo(&raw const x); }
}
