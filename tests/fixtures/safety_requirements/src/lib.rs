use std::ptr::NonNull;

/// # Safety
///
/// Requirements:
/// - valid_ptr: pointer must be non-null.
/// - initialized: pointer must reference initialized memory.
pub unsafe fn read_byte(ptr: *const u8) -> u8 {
    // SAFETY:
    // - valid_ptr: delegated to the caller.
    // - initialized: delegated to the caller.
    unsafe { *ptr }
}

unsafe fn uncontracted_operation() {}

pub fn satisfies_requirements() -> u8 {
    let byte = 7;
    let ptr = NonNull::from(&byte);

    // SAFETY:
    // - valid_ptr: NonNull was created from a live reference.
    // - initialized: `byte` was initialized above.
    unsafe { read_byte(ptr.as_ptr()) }
}

pub fn misses_one_requirement() -> u8 {
    let byte = 7;
    let ptr = NonNull::from(&byte);

    // SAFETY:
    // - valid_ptr: NonNull was created from a live reference.
    unsafe { read_byte(ptr.as_ptr()) }
}

pub fn misses_justification() {
    unsafe { uncontracted_operation() }
}
