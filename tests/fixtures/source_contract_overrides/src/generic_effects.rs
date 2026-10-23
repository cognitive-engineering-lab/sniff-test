pub fn allocation_contract() {}

pub fn file_contract() {}

pub unsafe fn safety_contract(pointer: *const u8) -> u8 {
    // SAFETY: pointer validity is delegated to the caller.
    unsafe { *pointer }
}

pub fn allocation_missing() {
    allocation_contract();
}

pub fn allocation_justified() {
    // ALLOCATION:
    // - audited: this caller accepts the allocation.
    allocation_contract();
}

pub fn file_missing() {
    file_contract();
}

pub fn file_justified() {
    // FILE:
    // - audited: this caller accepts the file change.
    file_contract();
}

pub fn safety_missing() -> u8 {
    let byte = 42;
    // SAFETY: the pointer is valid, but this reason lacks the named requirement.
    unsafe { safety_contract(&byte) }
}

pub fn safety_justified() -> u8 {
    let byte = 42;
    // SAFETY:
    // - valid: the pointer references a live initialized byte.
    unsafe { safety_contract(&byte) }
}
