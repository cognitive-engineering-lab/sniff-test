use std::ptr::NonNull;

/// # Safety
///
/// The caller must satisfy all listed requirements.
///
/// Requirements:
///
/// - valid_ptr: pointer must be non-null.
/// - initialized: pointer must reference initialized memory.
pub unsafe fn read_byte(ptr: *const u8) -> u8 {
    // SAFETY:
    // - valid_ptr: delegated to the caller.
    // - initialized: delegated to the caller.
    unsafe { *ptr }
}

pub unsafe fn undocumented_public(_ptr: *const u8) -> u8 {
    0
}

unsafe fn private_unsafe_no_docs() {}

pub fn satisfied_by_block_and_call() -> u8 {
    let mut byte = 7;
    let ptr = NonNull::from(&mut byte);

    // SAFETY:
    // - valid_ptr: NonNull was created from a live mutable reference.
    unsafe {
        // SAFETY:
        // - initialized: `byte` was initialized above.
        read_byte(ptr.as_ptr())
    }
}

pub fn missing_requirement() -> u8 {
    let mut byte = 7;
    let ptr = NonNull::from(&mut byte);

    // SAFETY:
    // - valid_ptr: NonNull was created from a live mutable reference.
    unsafe { read_byte(ptr.as_ptr()) }
}

pub fn missing_justification() {
    unsafe { private_unsafe_no_docs() }
}
