use std::ptr::NonNull;

pub fn panic_contract(flag: bool) {
    assert!(flag, "flag must be true");
}

pub fn panic_override_missing_marker(flag: bool) {
    panic_contract(flag);
}

pub fn panic_override_satisfied(flag: bool) {
    // PANIC:
    // - flag: caller checked the flag.
    panic_contract(flag);
}

pub unsafe fn synthetic_read(ptr: *const u8) -> u8 {
    // SAFETY:
    // - valid_ptr: delegated to the caller.
    // - initialized: delegated to the caller.
    unsafe { *ptr }
}

pub fn safety_override_missing_requirement() -> u8 {
    let byte = 7;
    let ptr = NonNull::from(&byte);

    // SAFETY:
    // - valid_ptr: NonNull was created from a live reference.
    unsafe { synthetic_read(ptr.as_ptr()) }
}

pub fn safety_override_satisfied() -> u8 {
    let byte = 7;
    let ptr = NonNull::from(&byte);

    // SAFETY:
    // - valid_ptr: NonNull was created from a live reference.
    // - initialized: `byte` was initialized above.
    unsafe { synthetic_read(ptr.as_ptr()) }
}
