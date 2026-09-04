pub fn transitively_invoke_assert_unsafe_precondition() {
    let v = [1, 2, 3];
    let (ptr, len) = (v.as_ptr(), v.len());
    // SAFETY: ptr and len are valid for the lifetime of v. 
    let _ = unsafe { std::slice::from_raw_parts(ptr, len) };
}