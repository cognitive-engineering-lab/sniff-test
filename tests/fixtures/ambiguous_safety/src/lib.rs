use std::ptr::NonNull;

/// # Safety
///
/// Requirements:
///
/// - valid_ptr: pointer must be non-null.
/// - valid_ptr: pointer must reference initialized memory.
pub unsafe fn read_duplicate(ptr: *const u8) -> u8 {
    // SAFETY: delegated to the caller.
    unsafe { *ptr }
}

pub fn duplicate_safety_marker() -> u8 {
    let byte = 7;
    let ptr = NonNull::from(&byte);

    // SAFETY:
    // - valid_ptr: pointer was created from a live reference.
    unsafe { read_duplicate(ptr.as_ptr()) }
}

unsafe fn perform() {}

macro_rules! perform_once {
    () => {{
        // SAFETY: this fixture's operation has no additional requirements.
        unsafe { perform() }
    }};
}

pub fn reused_macro_marker() {
    perform_once!();
    perform_once!();
}
