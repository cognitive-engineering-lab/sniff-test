pub fn foo() {
    let v = [1, 2, 3];
    // SAFETY: This is safe because we are creating a slice from a valid vector.
    #[allow(unused_variables)]
    unsafe {
        let a = unsafe_slice_producer(v.as_ptr(), v.len());
    }

    #[allow(unused_variables)]
    // SAFETY: This is safe because we are creating a slice from a valid vector.
    unsafe {
        let a = unsafe_slice_producer(v.as_ptr(), v.len());
    }
}

pub fn attributed_panic() {
    // PANIC: this fixture intentionally exercises the panic marker lookup.
    #[cfg(not(any()))]
    panic!("marker lookup fixture");
}

/// # Safety
///
/// the caller must ensure that the pointer and length are valid for the lifetime of the returned slice.
unsafe fn unsafe_slice_producer<'a>(ptr: *const i32, len: usize) -> &'a [i32] {
    unsafe { std::slice::from_raw_parts(ptr, len) }
}
