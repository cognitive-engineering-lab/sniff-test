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

pub fn unsafe_call_satisfies_all_requirements() -> u8 {
    let byte = 7;
    let ptr = NonNull::from(&byte);

    // SAFETY:
    // - valid_ptr: NonNull was created from a live reference.
    // - initialized: `byte` was initialized above.
    unsafe { read_byte(ptr.as_ptr()) }
}

pub fn unsafe_call_exposes_missing_requirement() -> u8 {
    let byte = 7;
    let ptr = NonNull::from(&byte);

    // SAFETY:
    // - valid_ptr: NonNull was created from a live reference.
    unsafe { read_byte(ptr.as_ptr()) }
}

pub fn unsafe_call_exposes_missing_justification() {
    unsafe { uncontracted_operation() }
}

/// # Safety
///
/// Requirements:
/// - valid_ptr: pointer must be non-null.
pub fn documented_obligation(_ptr: *const u8) {}

pub fn trusted_obligation_satisfies_requirement() {
    let byte = 7;
    let ptr = &raw const byte;

    // SAFETY:
    // - valid_ptr: pointer was created from a live reference.
    documented_obligation(ptr);
}

pub fn trusted_obligation_exposes_missing_requirement() {
    let byte = 7;
    documented_obligation(&raw const byte);
}
